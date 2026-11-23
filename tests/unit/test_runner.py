import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from guardian.core.exceptions import ToolNotAllowedError, UnsafeArgumentError
from guardian.execution import runner as runner_module
from guardian.execution.policies import ExecutionPolicy
from guardian.execution.results import ToolStatus
from guardian.execution.runner import ToolRunner


@pytest.fixture
def py_runner(monkeypatch) -> ToolRunner:
    """Runner whose only allowed tool, ``py``, resolves to the current interpreter."""
    monkeypatch.setattr(
        runner_module.shutil, "which", lambda tool: sys.executable if tool == "py" else None
    )
    return ToolRunner(ExecutionPolicy(allowed_tools=frozenset({"py", "absent"})))


def test_disallowed_tool_raises():
    with pytest.raises(ToolNotAllowedError):
        ToolRunner().run("rm", ["-rf", "/"], cwd=Path.cwd())


def test_missing_tool_returns_not_found(py_runner):
    result = py_runner.run("absent", [], cwd=Path.cwd())
    assert result.status is ToolStatus.NOT_FOUND
    assert not result.ran


def test_success_and_failure(py_runner, tmp_path):
    ok = py_runner.run("py", ["-c", "print('hi')"], cwd=tmp_path)
    assert ok.ok
    assert ok.stdout.strip() == "hi"
    bad = py_runner.run("py", ["-c", "import sys; sys.exit(3)"], cwd=tmp_path)
    assert bad.status is ToolStatus.FAILED
    assert bad.exit_code == 3
    assert bad.ran


def test_shell_metacharacters_are_not_interpreted(py_runner, tmp_path):
    result = py_runner.run(
        "py", ["-c", "import sys; print(sys.argv[1])", "a && echo pwned"], cwd=tmp_path
    )
    assert result.stdout.strip() == "a && echo pwned"


def test_timeout(py_runner, tmp_path):
    result = py_runner.run(
        "py", ["-c", "import time; time.sleep(10)"], cwd=tmp_path, timeout_seconds=0.5
    )
    assert result.status is ToolStatus.TIMEOUT
    assert "timed out" in result.error


def test_output_truncation(monkeypatch, tmp_path):
    monkeypatch.setattr(runner_module.shutil, "which", lambda _: sys.executable)
    runner = ToolRunner(ExecutionPolicy(allowed_tools=frozenset({"py"}), max_output_bytes=10))
    result = runner.run("py", ["-c", "print('x' * 100)"], cwd=tmp_path)
    assert result.stdout == "x" * 10
    assert result.stdout_truncated


def test_environment_is_scrubbed(py_runner, tmp_path, monkeypatch):
    monkeypatch.setenv("GUARDIAN_TEST_SECRET", "s3cret")
    result = py_runner.run(
        "py",
        ["-c", "import os; print(os.environ.get('GUARDIAN_TEST_SECRET', 'absent'))"],
        cwd=tmp_path,
    )
    assert result.stdout.strip() == "absent"


def test_batch_wrapper_rejects_cmd_metacharacters(monkeypatch, tmp_path):
    monkeypatch.setattr(runner_module.shutil, "which", lambda _: r"C:\tools\cdxgen.cmd")
    runner = ToolRunner()
    with pytest.raises(UnsafeArgumentError):
        runner.run("cdxgen", ["-o", "out.json & calc"], cwd=tmp_path)


def test_start_failure_returns_error(monkeypatch, tmp_path):
    monkeypatch.setattr(runner_module.shutil, "which", lambda _: str(tmp_path / "missing.exe"))
    result = ToolRunner().run("semgrep", ["--version"], cwd=tmp_path)
    assert result.status is ToolStatus.ERROR


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_git_hardening_reaches_git_spawned_by_other_tools(monkeypatch, tmp_path):
    """Semgrep runs `git` itself; a hostile core.fsmonitor must not execute through it."""
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    (repo / "a.txt").write_text("x")
    marker = tmp_path / "pwned"
    hook = tmp_path / "hook.py"
    hook.write_text(f"open({str(marker)!r}, 'w').close()\n")
    subprocess.run(
        ["git", "config", "core.fsmonitor", f'"{sys.executable}" "{hook}"'], cwd=repo, check=True
    )

    monkeypatch.setattr(runner_module.shutil, "which", lambda _: sys.executable)
    runner = ToolRunner(ExecutionPolicy(allowed_tools=frozenset({"scanner"})))
    child = "import subprocess; subprocess.run(['git', 'status', '--porcelain'], check=False)"
    result = runner.run("scanner", ["-c", child], cwd=repo)
    assert result.ran
    assert not marker.exists()

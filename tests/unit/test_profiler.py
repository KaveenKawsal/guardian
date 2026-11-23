import shutil
import subprocess
from pathlib import Path

import pytest

from guardian.core.config import GuardianSettings
from guardian.core.exceptions import RepositoryNotFoundError
from guardian.core.models import Ecosystem
from guardian.core.profiler import RepositoryProfiler
from guardian.execution import runner as runner_module
from guardian.execution.policies import ExecutionPolicy
from guardian.execution.runner import ToolRunner

requires_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


@pytest.fixture
def profiler() -> RepositoryProfiler:
    return RepositoryProfiler(settings=GuardianSettings(_env_file=None))


def test_missing_path_raises(profiler, tmp_path):
    with pytest.raises(RepositoryNotFoundError):
        profiler.profile(tmp_path / "nope")


def test_full_profile(profiler, make_repo):
    root = make_repo(
        {
            "app/main.py": "print('hello world')\n" * 10,
            "app/util.py": "x = 1\n",
            "web/index.ts": "export const a = 1;\n",
            "requirements.txt": "flask\n",
            "package.json": '{"dependencies": {"react": "18"}}',
            "Dockerfile": "FROM python:3.12\n",
            ".github/workflows/ci.yml": "on: push\n",
            ".github/dependabot.yml": "version: 2\n",
            "node_modules/left-pad/index.js": "module.exports = 1;\n",
        }
    )
    profile = profiler.profile(root)

    assert profile.name == "repo"
    assert profile.total_files == 8  # node_modules excluded
    assert profile.primary_language == "Python"
    assert {lang.name: lang.files for lang in profile.languages} == {"Python": 2, "TypeScript": 1}
    assert {e.ecosystem for e in profile.ecosystems} == {
        Ecosystem.PYTHON,
        Ecosystem.NODE,
        Ecosystem.CONTAINER,
    }
    assert profile.ecosystem(Ecosystem.JAVA) is None
    assert [(c.provider, c.path) for c in profile.ci] == [
        ("github-actions", ".github/workflows/ci.yml")
    ]
    assert not profile.git.is_repository
    # The profile must round-trip through JSON for storage and reports.
    assert type(profile).model_validate_json(profile.model_dump_json()) == profile


def test_file_limit_truncates_with_warning(make_repo):
    root = make_repo({f"f{i}.py": "" for i in range(5)})
    profiler = RepositoryProfiler(settings=GuardianSettings(_env_file=None, max_files=3))
    profile = profiler.profile(root)
    assert profile.truncated
    assert profile.total_files == 3
    assert any("File limit" in w for w in profile.warnings)


def test_symlinks_are_not_followed(profiler, make_repo, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("SECRET = 1\n")
    root = make_repo({"main.py": ""})
    try:
        (root / "linked").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks not permitted on this system")
    profile = profiler.profile(root)
    assert profile.total_files == 1
    assert profile.skipped_symlinks == 1


def test_git_not_installed(make_repo, monkeypatch):
    monkeypatch.setattr(runner_module.shutil, "which", lambda _: None)
    profiler = RepositoryProfiler(settings=GuardianSettings(_env_file=None))
    info = profiler.git_info(make_repo({"a.py": ""}))
    assert not info.is_repository
    assert info.error == "git is not installed"


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        cwd=root,
        check=True,
        capture_output=True,
    )


@requires_git
def test_git_info_for_clean_and_dirty_repo(profiler, make_repo):
    root = make_repo({"a.py": "x = 1\n"})
    _git(root, "init", "-q", "-b", "main")
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "init")

    info = profiler.git_info(root)
    assert info.is_repository
    assert info.branch == "main"
    assert info.head_commit
    assert len(info.head_commit) == 40
    assert info.is_dirty is False

    (root / "b.py").write_text("y = 2\n")
    assert profiler.git_info(root).is_dirty is True


@requires_git
def test_empty_repo_has_no_head(profiler, make_repo):
    root = make_repo({"a.py": ""})
    _git(root, "init", "-q", "-b", "main")
    info = profiler.git_info(root)
    assert info.is_repository
    assert info.head_commit is None
    assert info.branch == "main"


@requires_git
def test_malicious_fsmonitor_is_not_executed(make_repo, tmp_path):
    """A hostile .git/config must not run commands while Guardian reads git state."""
    root = make_repo({"a.py": ""})
    _git(root, "init", "-q")
    marker = tmp_path / "pwned"
    script = root / "hook.py"
    script.write_text(f"open({str(marker)!r}, 'w').close()\n")
    python = shutil.which("python") or "python"
    _git(root, "config", "core.fsmonitor", f'"{python}" "{script}"')

    runner = ToolRunner(ExecutionPolicy(timeout_seconds=30))
    RepositoryProfiler(settings=GuardianSettings(_env_file=None), runner=runner).git_info(root)
    assert not marker.exists()

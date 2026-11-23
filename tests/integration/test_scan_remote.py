"""``guardian scan`` with remote targets, cloned from local repositories over ``file://``."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from conftest import analysis
from typer.testing import CliRunner

from guardian.analysis.git_diff import ChangeAnalyzer
from guardian.analysis.osv import OsvScanner
from guardian.analysis.sbom import SbomGeneration, SbomGenerator
from guardian.analysis.semgrep import SemgrepScanner
from guardian.cli import scan as scan_module
from guardian.cli.main import app
from guardian.core.config import GuardianSettings
from guardian.execution.results import ToolResult, ToolStatus
from guardian.sources import RemoteTarget, clone, workspaces_dir
from guardian.storage.database import Database

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

cli = CliRunner()
REMOTE = "https://git.example.com/acme/upstream"


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=t", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
    )


@pytest.fixture
def upstream(tmp_path) -> Path:
    src = tmp_path / "upstream"
    src.mkdir()
    _git(src, "init", "-q", "-b", "main")
    (src / "package.json").write_text('{"dependencies": {"express": "4"}}')
    (src / "app.js").write_text("require('express')\n")
    _git(src, "add", ".")
    _git(src, "commit", "-qm", "init")
    return src


@pytest.fixture
def env(monkeypatch, tmp_path, upstream):
    """Isolated data dir, stubbed analyzers, and remote clones redirected to ``upstream``."""
    monkeypatch.setenv("GUARDIAN_DATA_DIR", str(tmp_path / "data"))

    def fake_generate(self, repo_root, work_dir):
        result = ToolResult(tool="cdxgen", args=[], status=ToolStatus.SKIPPED)
        return SbomGeneration(result=result, bom_path=None)

    monkeypatch.setattr(SbomGenerator, "generate", fake_generate)
    monkeypatch.setattr(OsvScanner, "scan", lambda *a, **k: analysis("osv-scanner", []))
    monkeypatch.setattr(SemgrepScanner, "scan", lambda *a, **k: analysis("semgrep", []))
    monkeypatch.setattr(ChangeAnalyzer, "analyze", lambda *a: analysis("git", status="skipped"))

    def local_clone(target: RemoteTarget, settings, runner):
        redirected = RemoteTarget(
            url=upstream.as_uri(), host=target.host, path=target.path, ref=target.ref
        )
        return clone(redirected, settings, runner, allow_file_transport=True)

    monkeypatch.setattr(scan_module, "clone", local_clone)
    return GuardianSettings(data_dir=tmp_path / "data")


def test_scan_remote_keeps_clone_and_groups_history(env):
    first = cli.invoke(app, ["scan", REMOTE])
    assert first.exit_code == 0, first.output
    assert "Cloning git.example.com/acme/upstream" in first.stdout
    assert "Clone kept at" in first.stdout
    flat = " ".join(first.stdout.split())  # Rich wraps long lines
    assert "npm install --package-lock-only --ignore-scripts" in flat
    assert "never runs package managers" in flat
    clones = list(workspaces_dir(env).glob("*/upstream"))
    assert len(clones) == 1
    assert (clones[0] / "app.js").exists()

    second = cli.invoke(app, ["scan", f'"{REMOTE}.git"'])
    assert second.exit_code == 0, second.output
    assert list(workspaces_dir(env).glob("*/upstream")) == clones
    with Database(env.database_path) as db:
        scans = db.scans.recent(str(clones[0].resolve()), limit=10)
    assert len(scans) == 2
    assert {s.repository_name for s in scans} == {"upstream"}


def test_scan_remote_json_keeps_stdout_clean(env):
    result = cli.invoke(app, ["scan", REMOTE, "--json", "--no-keep"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["profile"]["name"] == "upstream"
    assert "Cloning" in result.stderr
    assert "Clone deleted" in result.stderr
    assert not list(workspaces_dir(env).glob("*/upstream"))


def test_scan_remote_missing_ref(env):
    result = cli.invoke(app, ["scan", REMOTE, "--ref", "nope"])
    assert result.exit_code == 2
    assert "'nope' not found" in result.stderr


@pytest.mark.parametrize(
    ("target", "message"),
    [
        ("http://github.com/o/r", "insecure"),
        ("https://ghp_secret@github.com/o/r", "credentials"),
        ("ext::sh -c id", "transport"),
        ("git@github.com:o/r.git", "SSH"),
    ],
)
def test_scan_rejects_bad_targets(env, target, message):
    result = cli.invoke(app, ["scan", "--", target])
    assert result.exit_code == 2
    assert message in result.stderr
    assert "ghp_secret" not in result.stderr


def test_ref_with_local_path_is_rejected(env, tmp_path):
    result = cli.invoke(app, ["scan", str(tmp_path), "--ref", "main"])
    assert result.exit_code == 2
    assert "--ref only applies" in result.stderr


def test_prompt_when_interactive(env, upstream, monkeypatch):
    monkeypatch.setattr(scan_module, "_stdin_is_tty", lambda: True)
    result = cli.invoke(app, ["scan"], input=f"'{upstream}'\n")
    assert result.exit_code == 0, result.output
    assert "Paste a GitHub URL or a local path to scan" in result.stdout
    assert "Clone kept" not in result.stdout


def test_no_target_without_tty_scans_cwd(env, upstream, monkeypatch):
    monkeypatch.chdir(upstream)
    result = cli.invoke(app, ["scan", "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["profile"]["name"] == "upstream"

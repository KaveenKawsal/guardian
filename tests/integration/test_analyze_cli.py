"""``guardian analyze``: scan -> investigate -> remediate -> ui, with every step stubbed."""

import pytest
import typer
from remediation_fakes import init_repo, make_scan
from typer.testing import CliRunner

from guardian.cli import analyze as analyze_module
from guardian.cli.analyze import analyze
from guardian.core.config import GuardianSettings
from guardian.storage.database import Database


def _app():
    app = typer.Typer()
    app.command()(analyze)
    app.command("noop")(lambda: None)
    return app


@pytest.fixture
def world(tmp_path, monkeypatch):
    data = tmp_path / "data"
    monkeypatch.setenv("GUARDIAN_DATA_DIR", str(data))
    repo = tmp_path / "repo"
    head = init_repo(repo, {"package.json": "{}\n"})
    calls: list[tuple[str, dict]] = []
    scans: list[str] = []

    def fake_scan(**kwargs):
        calls.append(("scan", kwargs))
        scan_id = "fresh" if not scans else f"fresh{len(scans)}"
        scans.append(scan_id)
        with Database(GuardianSettings(_env_file=None, data_dir=data).database_path) as db:
            make_scan(db, scan_id, str(repo.resolve()), head=head)

    def recorder(name):
        return lambda **kwargs: calls.append((name, kwargs))

    monkeypatch.setattr(analyze_module, "scan", fake_scan)
    monkeypatch.setattr(analyze_module, "investigate", recorder("investigate"))
    monkeypatch.setattr(analyze_module, "remediate", recorder("remediate"))
    monkeypatch.setattr(analyze_module, "ui", recorder("ui"))
    return repo, head, data, calls


def test_runs_every_step_in_order(world):
    repo, _, _, calls = world
    result = CliRunner().invoke(_app(), ["analyze", str(repo), "--no-open", "--port", "0"])
    assert result.exit_code == 0, result.output
    assert [name for name, _ in calls] == ["scan", "investigate", "remediate", "ui"]
    kwargs = dict(calls)
    assert kwargs["investigate"]["scan_id"] == "fresh"
    assert kwargs["remediate"]["scan_id"] == "fresh"
    assert kwargs["remediate"]["no_jira"] is True
    assert kwargs["ui"] == {"port": 0, "no_open": True}


def test_reuses_scan_of_same_clean_commit_and_skips_ai(world):
    repo, head, data, calls = world
    with Database(GuardianSettings(_env_file=None, data_dir=data).database_path) as db:
        make_scan(db, "earlier", str(repo.resolve()), head=head)
    result = CliRunner().invoke(_app(), ["analyze", str(repo), "--no-ai", "--no-open"])
    assert result.exit_code == 0, result.output
    assert "Reusing scan" in result.output
    assert [name for name, _ in calls] == ["remediate", "ui"]
    assert dict(calls)["remediate"]["no_ai"] is True


def test_dirty_tree_or_rescan_flag_scans_again(world):
    repo, head, data, calls = world
    with Database(GuardianSettings(_env_file=None, data_dir=data).database_path) as db:
        make_scan(db, "earlier", str(repo.resolve()), head=head)
    result = CliRunner().invoke(_app(), ["analyze", str(repo), "--rescan", "--no-ai", "--no-open"])
    assert result.exit_code == 0, result.output
    assert calls[0][0] == "scan"
    calls.clear()
    (repo / "new.js").write_text("x\n")
    result = CliRunner().invoke(_app(), ["analyze", str(repo), "--no-ai", "--no-open"])
    assert result.exit_code == 0, result.output
    assert calls[0][0] == "scan"

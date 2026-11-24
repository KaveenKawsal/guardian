import importlib.util
import json
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from guardian.cli import report as report_cli
from guardian.cli.main import app as main_app
from guardian.cli.report import parse_formats, report
from guardian.reporting import report_data
from guardian.reporting.models import ReportFormat
from guardian.storage.scans import ScanNotFoundError

TESTS = Path(__file__).parents[1]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


make_report = _load("_report_render_helpers", TESTS / "unit" / "test_report_render.py").make_report
isolated = _load("_cli_helpers", TESTS / "integration" / "test_cli.py").isolated  # fixture

cli = CliRunner()
app = typer.Typer()
app.command()(report)  # main.py registration is done by the integrator
app.command("noop")(lambda: None)  # keep a multi-command app so "report" is a subcommand


@pytest.fixture
def fake_build(monkeypatch):
    calls = []

    def build(db, scan_id, settings, *, max_findings=500, include_code=True):
        calls.append({"scan_id": scan_id, "max": max_findings, "code": include_code})
        return make_report()

    monkeypatch.setattr(report_data, "build_report", build)
    return calls


def test_parse_formats():
    assert parse_formats(None) == [ReportFormat.HTML]
    assert parse_formats(["md,json", "html", "MD", "markdown"]) == [
        ReportFormat.MARKDOWN,
        ReportFormat.JSON,
        ReportFormat.HTML,
    ]
    with pytest.raises(typer.BadParameter):
        parse_formats(["pdf"])


def test_report_command_writes_files(isolated, make_repo, fake_build, tmp_path, monkeypatch):
    scan = cli.invoke(main_app, ["scan", str(make_repo({"package.json": "{}"}))])
    assert scan.exit_code == 0, scan.output
    opened = []
    monkeypatch.setattr(report_cli.webbrowser, "open", opened.append)
    out = tmp_path / "reports"
    result = cli.invoke(
        app,
        [
            "report",
            "-f",
            "md,json",
            "-f",
            "html",
            "-o",
            str(out),
            "--no-code",
            "--max-findings",
            "7",
            "--open",
        ],
    )
    assert result.exit_code == 0, result.output
    assert fake_build == [{"scan_id": fake_build[0]["scan_id"], "max": 7, "code": False}]
    names = sorted(p.name for p in out.iterdir())
    base = "guardian-report-demo-app-0123456789ab"
    assert names == [f"{base}.html", f"{base}.json", f"{base}.md"]
    assert "Wrote" in result.stdout
    assert "top 3 of 10" in result.stdout
    assert len(opened) == 1
    assert opened[0].startswith("file:")
    assert opened[0].endswith(".html")


def test_report_default_is_html(isolated, make_repo, fake_build, tmp_path, monkeypatch):
    cli.invoke(main_app, ["scan", str(make_repo({"package.json": "{}"}))])
    monkeypatch.chdir(tmp_path)
    result = cli.invoke(app, ["report"])
    assert result.exit_code == 0, result.output
    assert [p.suffix for p in (tmp_path / "guardian-reports").iterdir()] == [".html"]


def test_report_errors_exit_2(isolated, fake_build, monkeypatch, tmp_path):
    assert cli.invoke(app, ["report"]).exit_code == 2  # no scans yet
    assert cli.invoke(app, ["report", "-f", "pdf"]).exit_code == 2

    def missing(*args, **kwargs):
        msg = "No scan matches 'x'"
        raise ScanNotFoundError(msg)

    monkeypatch.setattr(report_data, "build_report", missing)
    monkeypatch.setattr(
        "guardian.storage.scans.ScanStore.resolve", lambda self, identifier, root=None: "x"
    )
    assert cli.invoke(app, ["report", "x", "-o", str(tmp_path)]).exit_code == 2


def test_report_unwritable_output_exits_2(isolated, make_repo, fake_build, tmp_path):
    cli.invoke(main_app, ["scan", str(make_repo({"package.json": "{}"}))])
    blocker = tmp_path / "file"
    blocker.write_text("x")
    result = cli.invoke(app, ["report", "-o", str(blocker / "sub")])
    assert result.exit_code == 2
    assert "Could not write reports" in result.output


def test_scan_with_report(isolated, make_repo, fake_build, tmp_path, monkeypatch):
    root = make_repo({"package.json": "{}"})
    monkeypatch.chdir(tmp_path)
    result = cli.invoke(main_app, ["scan", str(root), "--report-format", "md,json"])
    assert result.exit_code == 0, result.output
    out = tmp_path / "guardian-reports"
    assert sorted(p.suffix for p in out.iterdir()) == [".json", ".md"]
    assert "Wrote" in result.stdout


def test_scan_json_with_report_keeps_stdout_clean(
    isolated, make_repo, fake_build, tmp_path, monkeypatch
):
    root = make_repo({"package.json": "{}"})
    monkeypatch.chdir(tmp_path)
    result = cli.invoke(main_app, ["scan", str(root), "--json", "--report"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["scan"]["status"] == "completed"
    assert "Wrote" in result.stderr
    assert [p.suffix for p in (tmp_path / "guardian-reports").iterdir()] == [".html"]


def test_scan_rejects_bad_report_format_before_scanning(isolated, make_repo, fake_build):
    result = cli.invoke(main_app, ["scan", str(make_repo({})), "--report-format", "pdf"])
    assert result.exit_code == 2
    assert fake_build == []

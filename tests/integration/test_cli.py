import json

from typer.testing import CliRunner

from guardian import __version__
from guardian.cli.main import app

cli = CliRunner()


def test_version():
    result = cli.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_profile_summary(make_repo):
    root = make_repo({"app.py": "import flask\n", "requirements.txt": "flask\n"})
    result = cli.invoke(app, ["profile", str(root)])
    assert result.exit_code == 0, result.output
    assert "Python" in result.stdout
    assert "Flask" in result.stdout


def test_profile_json_and_output_file(make_repo, tmp_path):
    root = make_repo({"package.json": '{"dependencies": {"express": "4"}}'})
    out = tmp_path / "profile.json"
    result = cli.invoke(app, ["profile", str(root), "--json", "-o", str(out)])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["ecosystems"][0]["frameworks"][0]["name"] == "Express"
    assert json.loads(out.read_text()) == data


def test_profile_missing_path(tmp_path):
    result = cli.invoke(app, ["profile", str(tmp_path / "missing")])
    assert result.exit_code == 2


def test_doctor_runs():
    result = cli.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "semgrep" in result.stdout


# --- scan / history / deps --------------------------------------------------------------

from pathlib import Path  # noqa: E402

import pytest  # noqa: E402
from conftest import analysis  # noqa: E402

from guardian.analysis.git_diff import ChangeAnalyzer  # noqa: E402
from guardian.analysis.osv import OsvScanner, parse_osv_output  # noqa: E402
from guardian.analysis.sbom import SbomGeneration, SbomGenerator  # noqa: E402
from guardian.analysis.semgrep import SemgrepScanner  # noqa: E402
from guardian.core.models import CodeDetails, Finding, FindingKind, Severity  # noqa: E402
from guardian.execution.results import ToolResult, ToolStatus  # noqa: E402

FIXTURES = Path(__file__).parents[1] / "fixtures"
NODE_BOM = (FIXTURES / "sbom" / "node-express.cdx.json").read_bytes()
OSV_OUTPUT = (FIXTURES / "osv" / "node.osv.json").read_bytes()


@pytest.fixture
def isolated(monkeypatch, tmp_path):
    """Fresh data dir and a canned cdxgen result for every CLI scan."""
    monkeypatch.setenv("GUARDIAN_DATA_DIR", str(tmp_path / "data"))

    def fake_generate(self, repo_root, work_dir):
        bom = work_dir / "bom.json"
        bom.write_bytes(NODE_BOM)
        result = ToolResult(tool="cdxgen", args=[], status=ToolStatus.SUCCESS, exit_code=0)
        return SbomGeneration(result=result, bom_path=bom)

    monkeypatch.setattr(SbomGenerator, "generate", fake_generate)

    def fake_osv(self, repo_root, work_dir, sbom, raw_sbom, excluded=frozenset()):
        return analysis("osv-scanner", parse_osv_output(OSV_OUTPUT, sbom)[0])

    def fake_semgrep(self, profile, work_dir, excluded=frozenset()):
        hostile = Finding(
            id="code00000000beef",
            kind=FindingKind.CODE,
            title="[red]spoofed[/red] in app.js:1",
            severity=Severity.HIGH,
            tool="semgrep",
            path="app.js",
            start_line=1,
            details=CodeDetails(rule_id="js.[bold]x[/bold]", message="Use [link=evil]x[/link]"),
        )
        return analysis("semgrep", [hostile])

    monkeypatch.setattr(OsvScanner, "scan", fake_osv)
    monkeypatch.setattr(SemgrepScanner, "scan", fake_semgrep)
    monkeypatch.setattr(
        ChangeAnalyzer, "analyze", lambda self, p: analysis("git", status="skipped")
    )


def test_scan_history_deps(isolated, make_repo):
    root = make_repo({"package.json": '{"dependencies": {"express": "4"}}'})
    result = cli.invoke(app, ["scan", str(root)])
    assert result.exit_code == 0, result.output
    assert "7 components" in result.stdout
    assert "completed" in result.stdout

    history = cli.invoke(app, ["history", str(root)])
    assert "completed" in history.stdout

    direct = cli.invoke(app, ["deps"])
    assert direct.exit_code == 0, direct.output
    assert "express@4.17.1" in direct.stdout
    assert "accepts" not in direct.stdout

    everything = cli.invoke(app, ["deps", "latest", "--all"])
    assert "accepts@1.3.8" in everything.stdout

    why = cli.invoke(app, ["deps", "--why", "mime-types"])
    assert why.exit_code == 0, why.output
    assert "express@4.17.1 -> accepts@1.3.8 -> mime-types@2.1.35" in why.stdout

    why_json = json.loads(cli.invoke(app, ["deps", "--why", "express", "--json"]).stdout)
    assert why_json[0]["paths"] == [["express@4.17.1"]]

    all_json = json.loads(cli.invoke(app, ["deps", "--json", "--all"]).stdout)
    assert len(all_json) == 7

    missing = cli.invoke(app, ["deps", "--why", "left-pad"])
    assert missing.exit_code == 1


def test_scan_json(isolated, make_repo):
    root = make_repo({"package.json": "{}"})
    data = json.loads(cli.invoke(app, ["scan", str(root), "--json"]).stdout)
    assert data["scan"]["status"] == "completed"
    assert len(data["sbom"]["components"]) == 7


def test_history_empty_and_unknown_scan(isolated):
    assert "No scans recorded yet" in cli.invoke(app, ["history"]).stdout
    result = cli.invoke(app, ["deps", "nope"])
    assert result.exit_code == 2


def test_deps_for_scan_without_sbom(isolated, make_repo):
    cli.invoke(app, ["scan", str(make_repo({"main.go": ""}))])
    assert cli.invoke(app, ["deps"]).exit_code == 1


def test_scan_missing_path(isolated, tmp_path):
    assert cli.invoke(app, ["scan", str(tmp_path / "missing")]).exit_code == 2


# --- findings / explain / graph --------------------------------------------------------


def test_findings_and_explain(isolated, make_repo):
    root = make_repo({"package.json": '{"dependencies": {"express": "4", "lodash": "4"}}'})
    scan = cli.invoke(app, ["scan", str(root)])
    assert scan.exit_code == 0, scan.output
    assert "Security findings" in scan.stdout

    listing = cli.invoke(app, ["findings"])
    assert listing.exit_code == 0, listing.output
    assert "CVE-2021-23337 in" in listing.stdout
    # Untrusted text is shown literally, never interpreted as Rich markup.
    assert "[red]spoofed[/red]" in listing.stdout

    only_code = json.loads(cli.invoke(app, ["findings", "--kind", "code", "--json"]).stdout)
    assert [f["id"] for f in only_code] == ["code00000000beef"]
    high_up = json.loads(cli.invoke(app, ["findings", "-s", "high", "--json"]).stdout)
    assert {f["severity"] for f in high_up} == {"high"}

    vuln = next(
        f
        for f in json.loads(cli.invoke(app, ["findings", "--json"]).stdout)
        if f["details"].get("vulnerability_id") == "CVE-2021-23337"
    )
    explained = cli.invoke(app, ["explain", vuln["id"][:8]])
    assert explained.exit_code == 0, explained.output
    assert "lodash is a direct dependency" in explained.stdout
    assert "Upgrade lodash to 4.17.21" in explained.stdout
    assert "[advisory]" in explained.stdout

    code = cli.invoke(app, ["explain", "code0000"])
    assert "Use [link=evil]x[/link]" in code.stdout
    assert "js.[bold]x[/bold]" in code.stdout

    as_json = json.loads(cli.invoke(app, ["explain", vuln["id"], "--json"]).stdout)
    assert as_json["introduction_paths"] == [["lodash@4.17.20"]]
    assert cli.invoke(app, ["explain", "nope"]).exit_code == 2


def test_graph_export(isolated, make_repo, tmp_path):
    cli.invoke(app, ["scan", str(make_repo({"package.json": "{}"}))])
    out = tmp_path / "graph"
    result = cli.invoke(app, ["graph", "-o", str(out), "--no-embed"])
    assert result.exit_code == 0, result.output
    assert (out / "index.html").is_file()
    assert json.loads((out / "graph.json").read_text(encoding="utf-8"))["meta"]["components"] == 7


def test_graph_without_sbom(isolated, make_repo, tmp_path):
    cli.invoke(app, ["scan", str(make_repo({"main.go": ""}))])
    assert cli.invoke(app, ["graph", "-o", str(tmp_path / "g")]).exit_code == 1


# --- code (phase 4) --------------------------------------------------------------------

CODE_REPO = {
    "package.json": '{"main": "app.js", "dependencies": {"express": "4", "lodash": "4"}}',
    "app.js": (
        "function run(a) {\n"
        "  return _.template(a);\n"
        "}\n"
        'const _ = require("lodash");\n'
        'const express = require("express");\n'
        "const app = express();\n"
        'app.get("/x", run);\n'
        "app.listen(3000);\n"
    ),
}


def test_scan_shows_code_and_code_commands(isolated, make_repo):
    root = make_repo(CODE_REPO)
    scan = cli.invoke(app, ["scan", str(root)])
    assert scan.exit_code == 0, scan.output
    assert "1 files indexed" in scan.stdout
    assert "2 external packages imported" in scan.stdout
    assert "indexer: success" in scan.stdout

    summary = cli.invoke(app, ["code"])
    assert summary.exit_code == 0, summary.output
    assert "Files: 1 (1 javascript)" in summary.stdout
    assert "Most imported external packages" in summary.stdout
    assert "lodash" in summary.stdout

    as_json = json.loads(cli.invoke(app, ["code", "latest", "--json"]).stdout)
    assert as_json["files"] == 1
    assert as_json["external_packages"] == {"express": 1, "lodash": 1}
    assert as_json["entry_points_by_kind"]["http-route"] == 1

    uses = cli.invoke(app, ["code", "--uses", "LoDash"])
    assert uses.exit_code == 0, uses.output
    assert "app.js:4" in uses.stdout
    assert "template" in uses.stdout
    uses_json = json.loads(cli.invoke(app, ["code", "--uses", "lodash", "--json"]).stdout)
    assert [i["line"] for i in uses_json["imports"]] == [4]
    assert uses_json["members"] == {"template": 1}
    none = cli.invoke(app, ["code", "--uses", "left-pad"])
    assert none.exit_code == 0
    assert "does not import" in none.stdout

    entries = cli.invoke(app, ["code", "--entry-points"])
    assert entries.exit_code == 0, entries.output
    assert "GET /x" in entries.stdout
    assert "server-listen" in entries.stdout
    entries_json = json.loads(cli.invoke(app, ["code", "--entry-points", "--json"]).stdout)
    assert {e["kind"] for e in entries_json} >= {"http-route", "server-listen", "package-main"}

    explained = cli.invoke(app, ["explain", "code0000"])
    assert "Symbol: app.js::run" in explained.stdout
    vuln = next(
        f
        for f in json.loads(cli.invoke(app, ["findings", "--json"]).stdout)
        if f["details"].get("vulnerability_id") == "CVE-2021-23337"
    )
    explained = cli.invoke(app, ["explain", vuln["id"]])
    assert "[code-usage] Imported in 1 file(s): app.js:4; calls: template (1)" in (explained.stdout)


def test_scan_json_has_code_counts(isolated, make_repo):
    data = json.loads(cli.invoke(app, ["scan", str(make_repo(CODE_REPO)), "--json"]).stdout)
    assert data["code"]["files"] == 1
    assert data["code"]["symbols"] == 1
    assert "imports" not in data["code"] or isinstance(data["code"]["imports"], int)


def test_code_without_index(isolated, make_repo):
    root = make_repo({"package.json": "{}"})
    data = json.loads(cli.invoke(app, ["scan", str(root), "--json"]).stdout)
    assert data["code"] is None
    result = cli.invoke(app, ["code"])
    assert result.exit_code == 1
    assert "no code index" in result.output


def test_code_output_escapes_repository_text(isolated, make_repo):
    from guardian.core.config import GuardianSettings
    from guardian.core.models import (
        CodeIndex,
        EntryPoint,
        EntryPointKind,
        FileIndex,
        ImportStyle,
        ImportTarget,
        ResolvedCall,
        ResolvedImport,
        SourceLanguage,
    )
    from guardian.storage.database import Database

    cli.invoke(app, ["scan", str(make_repo({"package.json": "{}"}))])
    evil = "[red]evil[/red]"
    index = CodeIndex(
        files=[
            FileIndex(
                path="[b]a[/b].js",
                language=SourceLanguage.JAVASCRIPT,
                sha256="0",
                size=1,
                line_count=1,
            )
        ],
        imports=[
            ResolvedImport(
                path="[b]a[/b].js",
                line=1,
                module=evil,
                style=ImportStyle.ES,
                target=ImportTarget.EXTERNAL,
                package=evil,
            )
        ],
        calls=[
            ResolvedCall(
                path="[b]a[/b].js",
                line=2,
                callee="x.[i]m[/i]",
                caller_id="[b]a[/b].js::[u]f[/u]",
                package=evil,
                member="[i]m[/i]",
            )
        ],
        entry_points=[
            EntryPoint(
                path="[b]a[/b].js",
                line=3,
                kind=EntryPointKind.HTTP_ROUTE,
                detail="GET /[blink]x[/blink]",
            )
        ],
    )
    with Database(GuardianSettings().database_path) as db:
        db.code.save(db.scans.resolve("latest"), index)

    summary = cli.invoke(app, ["code"])
    assert evil in summary.stdout
    uses = cli.invoke(app, ["code", "--uses", evil])
    assert uses.exit_code == 0, uses.output
    for text in (evil, "[b]a[/b].js:1", "[i]m[/i]", "[u]f[/u]"):
        assert text in uses.stdout
    entries = cli.invoke(app, ["code", "--entry-points"])
    assert "GET /[blink]x[/blink]" in entries.stdout

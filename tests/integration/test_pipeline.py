import shutil
import threading
from pathlib import Path

import pytest
from conftest import StubAnalyzer, analysis

from guardian.analysis.osv import parse_osv_output
from guardian.analysis.sbom import SbomGeneration, SbomGenerator
from guardian.core.config import GuardianSettings
from guardian.core.exceptions import RepositoryNotFoundError, UnsafeArgumentError
from guardian.core.models import (
    CodeIndex,
    DirectSource,
    EvidenceKind,
    FileIndex,
    ScanStatus,
    SourceLanguage,
)
from guardian.execution.results import ToolResult, ToolStatus
from guardian.execution.runner import ToolRunner
from guardian.orchestration.pipeline import ScanPipeline
from guardian.storage.database import Database

FIXTURES = Path(__file__).parents[1] / "fixtures" / "sbom"
NODE_REPO = {"package.json": '{"dependencies": {"express": "4", "lodash": "4"}}'}


class FixtureGenerator(SbomGenerator):
    """Writes a canned SBOM instead of running cdxgen."""

    def __init__(self, content: bytes | None, status=ToolStatus.SUCCESS, error=None):
        super().__init__(ToolRunner())
        self.content, self.status, self.error = content, status, error

    def generate(self, repo_root, work_dir):
        if self.error:
            raise self.error
        bom = None
        if self.content is not None:
            bom = work_dir / "bom.json"
            bom.write_bytes(self.content)
        result = ToolResult(tool="cdxgen", args=[], status=self.status, exit_code=0)
        return SbomGeneration(result=result, bom_path=bom)


@pytest.fixture
def settings(tmp_path):
    return GuardianSettings(_env_file=None, data_dir=tmp_path / "data")


@pytest.fixture
def db(settings):
    with Database(settings.database_path) as database:
        yield database


def _pipeline(db, settings, generator, **analyzers):
    """Pipeline whose security analyzers are stubs unless overridden (no network in tests)."""
    defaults = {
        "osv_scanner": StubAnalyzer(analysis("osv-scanner")),
        "semgrep_scanner": StubAnalyzer(analysis("semgrep")),
        "change_analyzer": StubAnalyzer(analysis("git", status="skipped")),
    }
    return ScanPipeline(db, settings, sbom_generator=generator, **{**defaults, **analyzers})


def test_completed_scan_is_persisted(db, settings, make_repo):
    root = make_repo(NODE_REPO)
    generator = FixtureGenerator((FIXTURES / "node-express.cdx.json").read_bytes())
    outcome = _pipeline(db, settings, generator).run(root)

    assert outcome.record.status is ScanStatus.COMPLETED
    assert outcome.record.component_count == 7
    assert outcome.sbom.direct_source is DirectSource.SBOM_AND_MANIFEST
    assert [c.name for c in outcome.graph.direct_dependencies()] == ["express", "lodash"]
    assert db.sboms.load(outcome.record.id) == outcome.sbom
    assert db.scans.resolve("latest") == outcome.record.id


def test_missing_cdxgen_gives_partial_scan(db, settings, make_repo, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _: None)
    outcome = ScanPipeline(db, settings).run(make_repo(NODE_REPO))  # every tool missing
    assert outcome.record.status is ScanStatus.PARTIAL
    assert outcome.sbom is None
    assert outcome.record.tool_runs[0].status == "not_found"
    assert any("No SBOM produced" in w for w in outcome.record.warnings)
    assert outcome.graph.components() == []


def test_no_manifests_skips_sbom(db, settings, make_repo):
    outcome = _pipeline(db, settings, FixtureGenerator(None)).run(make_repo({"main.go": ""}))
    assert outcome.record.status is ScanStatus.COMPLETED
    assert outcome.record.tool_runs[0].status == "skipped"


def test_unparseable_sbom_is_partial(db, settings, make_repo):
    outcome = _pipeline(db, settings, FixtureGenerator(b"{oops")).run(make_repo(NODE_REPO))
    assert outcome.record.status is ScanStatus.PARTIAL
    assert any("Invalid CycloneDX" in w for w in outcome.record.warnings)


def test_oversized_sbom_is_rejected(db, tmp_path, make_repo):
    settings = GuardianSettings(_env_file=None, data_dir=tmp_path / "d", max_sbom_bytes=10)
    content = (FIXTURES / "node-express.cdx.json").read_bytes()
    outcome = _pipeline(db, settings, FixtureGenerator(content)).run(make_repo(NODE_REPO))
    assert outcome.record.status is ScanStatus.PARTIAL
    assert any("byte limit" in w for w in outcome.record.warnings)


def test_generator_refusal_is_partial(db, settings, make_repo):
    generator = FixtureGenerator(None, error=UnsafeArgumentError("bad path"))
    outcome = _pipeline(db, settings, generator).run(make_repo(NODE_REPO))
    assert outcome.record.status is ScanStatus.PARTIAL
    assert outcome.record.tool_runs[0].error == "bad path"


def test_failed_tool_records_stderr(db, settings, make_repo):
    class StderrGenerator(FixtureGenerator):
        def generate(self, repo_root, work_dir):
            result = ToolResult(
                tool="cdxgen", args=[], status=ToolStatus.FAILED, exit_code=1, stderr="x\nboom\n"
            )
            return SbomGeneration(result=result, bom_path=None)

    outcome = _pipeline(db, settings, StderrGenerator(None)).run(make_repo(NODE_REPO))
    assert outcome.record.tool_runs[0].error == "boom"


def test_unexpected_error_marks_scan_failed(db, settings, make_repo):
    generator = FixtureGenerator(None, error=RuntimeError("kaboom"))
    with pytest.raises(RuntimeError):
        _pipeline(db, settings, generator).run(make_repo(NODE_REPO))
    assert db.scans.recent()[0].status is ScanStatus.FAILED


def test_invalid_path_stores_nothing(db, settings, tmp_path):
    with pytest.raises(RepositoryNotFoundError):
        _pipeline(db, settings, FixtureGenerator(None)).run(tmp_path / "missing")
    assert db.scans.recent() == []


# --- security stage -------------------------------------------------------------------

OSV_OUTPUT = (Path(__file__).parents[1] / "fixtures" / "osv" / "node.osv.json").read_bytes()


def _code_finding():
    from guardian.core.models import CodeDetails, Finding, FindingKind, Severity

    return Finding(
        id="code0001",
        kind=FindingKind.CODE,
        title="rule in app.js:1",
        severity=Severity.CRITICAL,
        tool="semgrep",
        path="app.js",
        start_line=1,
        details=CodeDetails(rule_id="rule", message="m"),
    )


def test_security_findings_are_merged_linked_and_persisted(db, settings, make_repo):
    root = make_repo(NODE_REPO)
    raw = (FIXTURES / "node-express.cdx.json").read_bytes()

    class SbomAwareOsv(StubAnalyzer):
        def scan(self, repo_root, work_dir, sbom, raw_sbom, excluded=frozenset()):
            self.calls += 1
            assert raw_sbom == raw  # OSV receives Guardian's SBOM
            return analysis("osv-scanner", parse_osv_output(OSV_OUTPUT, sbom)[0])

    git = StubAnalyzer(analysis("git"), blamed_commit="f" * 40)
    outcome = _pipeline(
        db,
        settings,
        FixtureGenerator(raw),
        osv_scanner=SbomAwareOsv(analysis("osv-scanner")),
        semgrep_scanner=StubAnalyzer(analysis("semgrep", [_code_finding()])),
        change_analyzer=git,
    ).run(root)

    assert outcome.record.status is ScanStatus.COMPLETED
    assert outcome.record.finding_count == 6
    assert outcome.findings[0].id == "code0001"  # critical first
    assert git.blame_calls == 1
    assert outcome.findings[0].introduced_by == "f" * 40
    assert outcome.graph.introducing_change("code0001").commit == "f" * 40
    lodash = outcome.graph.find("lodash")[0]
    assert len(outcome.graph.findings_for_component(lodash.ref)) == 2
    assert [c.name for c in outcome.graph.vulnerable_components()] == ["lodash"]
    assert db.findings.load(outcome.record.id) == outcome.findings
    assert [c.commit for c in db.findings.changes(outcome.record.id)] == ["f" * 40]


def test_blame_is_skipped_when_git_analysis_did_not_run(db, settings, make_repo):
    git = StubAnalyzer(analysis("git", status="skipped"), blamed_commit="f" * 40)
    outcome = _pipeline(
        db,
        settings,
        FixtureGenerator(None),
        semgrep_scanner=StubAnalyzer(analysis("semgrep", [_code_finding()])),
        change_analyzer=git,
    ).run(make_repo({"app.js": "x"}))
    assert git.blame_calls == 0
    assert outcome.findings[0].introduced_by is None


def test_missing_scanner_makes_the_scan_partial(db, settings, make_repo):
    outcome = _pipeline(
        db,
        settings,
        FixtureGenerator(None),
        semgrep_scanner=StubAnalyzer(analysis("semgrep", status="not_found")),
    ).run(make_repo({"app.js": "x"}))
    assert outcome.record.status is ScanStatus.PARTIAL


def test_analyzer_refusal_becomes_an_errored_run(db, settings, make_repo):
    outcome = _pipeline(
        db,
        settings,
        FixtureGenerator(None),
        semgrep_scanner=StubAnalyzer(UnsafeArgumentError("refused")),
    ).run(make_repo({"app.js": "x"}))
    run = next(r for r in outcome.record.tool_runs if r.tool == "semgrep")
    assert run.status == "error"
    assert run.error == "refused"
    assert outcome.record.status is ScanStatus.PARTIAL


def test_osv_is_skipped_without_manifests(db, settings, make_repo):
    osv = StubAnalyzer(analysis("osv-scanner"))
    outcome = _pipeline(db, settings, FixtureGenerator(None), osv_scanner=osv).run(
        make_repo({"main.go": ""})
    )
    assert osv.calls == 0
    assert next(r for r in outcome.record.tool_runs if r.tool == "osv-scanner").status == "skipped"


# --- codebase understanding (phase 4) --------------------------------------------------

APP_JS = (
    'const _ = require("lodash");\n'
    'import express from "express";\n'
    "function run(a) {\n"
    "  return _.template(a);\n"
    "}\n"
    "_.merge({}, {});\n"
    "const app = express();\n"
    'app.get("/x", run);\n'
    "app.listen(3000);\n"
)


class RecordingIndexer:
    """Stands in for RepositoryIndexer; records the calling thread."""

    def __init__(self, result):
        self.result = result
        self.threads = []

    def index(self, profile, sbom):
        self.threads.append(threading.current_thread())
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _indexer_run(outcome):
    return next(r for r in outcome.record.tool_runs if r.tool == "indexer")


def _osv_from_fixture():
    class SbomAwareOsv(StubAnalyzer):
        def scan(self, repo_root, work_dir, sbom, raw_sbom, excluded=frozenset()):
            return analysis("osv-scanner", parse_osv_output(OSV_OUTPUT, sbom)[0])

    return SbomAwareOsv(analysis("osv-scanner"))


def test_code_index_is_stored_and_findings_are_enriched(db, settings, make_repo):
    root = make_repo({**NODE_REPO, "app.js": APP_JS})
    semgrep_hit = _code_finding().model_copy(update={"start_line": 4})
    outcome = _pipeline(
        db,
        settings,
        FixtureGenerator((FIXTURES / "node-express.cdx.json").read_bytes()),
        osv_scanner=_osv_from_fixture(),
        semgrep_scanner=StubAnalyzer(analysis("semgrep", [semgrep_hit])),
    ).run(root)

    assert outcome.record.status is ScanStatus.COMPLETED
    assert _indexer_run(outcome).status == "success"
    index = outcome.code_index
    assert [f.path for f in index.files] == ["app.js"]
    assert db.code.load(outcome.record.id) == index

    saved = db.findings.load(outcome.record.id)
    assert saved == outcome.findings
    code = next(f for f in saved if f.id == "code0001")
    assert code.symbol_id == "app.js::run"
    lodash = [f for f in saved if f.component_ref == "pkg:npm/lodash@4.17.20"]
    assert lodash
    for finding in lodash:
        usage = [e for e in finding.evidence if e.kind is EvidenceKind.CODE_USAGE]
        assert len(usage) == 1
        assert usage[0].summary == (
            "Imported in 1 file(s): app.js:1; calls: merge (1), template (1)"
        )
        assert (usage[0].path, usage[0].line) == ("app.js", 1)


def test_indexing_disabled_is_skipped(db, tmp_path, make_repo):
    settings = GuardianSettings(_env_file=None, data_dir=tmp_path / "d", index_source=False)
    indexer = RecordingIndexer(CodeIndex())
    outcome = _pipeline(db, settings, FixtureGenerator(None), indexer=indexer).run(
        make_repo({"app.js": APP_JS})
    )
    assert indexer.threads == []
    assert _indexer_run(outcome).status == "skipped"
    assert outcome.code_index is None
    assert db.code.load(outcome.record.id) is None
    assert outcome.record.status is ScanStatus.COMPLETED


def test_no_source_files_is_skipped(db, settings, make_repo):
    outcome = _pipeline(db, settings, FixtureGenerator(None)).run(make_repo({"main.go": ""}))
    assert _indexer_run(outcome).status == "skipped"
    assert outcome.code_index is None
    assert db.code.load(outcome.record.id) is None


def test_indexer_error_gives_partial_scan(db, settings, make_repo):
    indexer = RecordingIndexer(RuntimeError("parser exploded"))
    outcome = _pipeline(
        db,
        settings,
        FixtureGenerator(None),
        semgrep_scanner=StubAnalyzer(analysis("semgrep", [_code_finding()])),
        indexer=indexer,
    ).run(make_repo({"app.js": APP_JS}))
    run = _indexer_run(outcome)
    assert run.status == "error"
    assert "parser exploded" in run.error
    assert outcome.record.status is ScanStatus.PARTIAL
    assert outcome.code_index is None
    assert any("Source indexing failed" in w for w in outcome.record.warnings)
    assert outcome.findings[0].symbol_id is None  # findings survive without enrichment


def test_indexing_runs_on_the_main_thread_with_warnings(db, settings, make_repo):
    file_index = FileIndex(
        path="app.js", language=SourceLanguage.JAVASCRIPT, sha256="0", size=1, line_count=1
    )
    index = CodeIndex(
        files=[file_index], skipped_files={"extract-error": 2}, warnings=["indexer said hi"]
    )
    indexer = RecordingIndexer(index)
    outcome = _pipeline(db, settings, FixtureGenerator(None), indexer=indexer).run(
        make_repo({"app.js": APP_JS})
    )
    assert indexer.threads == [threading.main_thread()]
    assert _indexer_run(outcome).status == "success"
    assert "indexer said hi" in outcome.record.warnings
    assert "Source indexing: 2 file(s) could not be parsed" in outcome.record.warnings
    assert db.code.load(outcome.record.id) == index


def test_knowledge_graph_includes_the_code_layer(db, settings, make_repo):
    """Integration of the pipeline (code index) with the graph code layer."""
    root = make_repo(
        {
            **NODE_REPO,
            "app.js": "const _ = require('lodash');\nfunction render(t) { return _.template(t); }\n",
        }
    )
    raw = (FIXTURES / "node-express.cdx.json").read_bytes()
    outcome = _pipeline(db, settings, FixtureGenerator(raw)).run(root)
    lodash = outcome.graph.find("lodash")[0]
    assert outcome.code_index is not None
    assert outcome.graph.is_imported(lodash.ref)
    assert outcome.graph.importers_of(lodash.ref) == ["app.js"]
    assert outcome.graph.symbol("app.js::render") is not None

import shutil
from pathlib import Path

import pytest
from conftest import StubAnalyzer, analysis

from guardian.analysis.osv import parse_osv_output
from guardian.analysis.sbom import SbomGeneration, SbomGenerator
from guardian.core.config import GuardianSettings
from guardian.core.exceptions import RepositoryNotFoundError, UnsafeArgumentError
from guardian.core.models import DirectSource, ScanStatus
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

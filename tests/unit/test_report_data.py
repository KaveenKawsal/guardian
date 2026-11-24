from datetime import UTC, datetime
from pathlib import Path

import pytest
from conftest import StubAnalyzer, analysis

from guardian.analysis.osv import parse_osv_output
from guardian.analysis.sbom import SbomGeneration, SbomGenerator
from guardian.core.config import GuardianSettings
from guardian.core.models import (
    ChangeCategory,
    ChangeDetails,
    CodeDetails,
    CodeIndex,
    Component,
    DependencyEdge,
    DirectSource,
    Ecosystem,
    EcosystemProfile,
    FileIndex,
    Finding,
    FindingKind,
    GitInfo,
    ManifestFile,
    ManifestKind,
    Priority,
    RepositoryProfile,
    Sbom,
    ScanStatus,
    Severity,
    SourceLanguage,
    ToolRunSummary,
    VulnerabilityDetails,
)
from guardian.execution.results import ToolResult, ToolStatus
from guardian.execution.runner import ToolRunner
from guardian.orchestration.pipeline import ScanPipeline
from guardian.reporting.report_data import build_report, remediation
from guardian.storage.database import Database
from guardian.storage.scans import ScanNotFoundError

FIXTURES = Path(__file__).parents[1] / "fixtures"


@pytest.fixture
def settings(tmp_path):
    return GuardianSettings(_env_file=None, data_dir=tmp_path / "data")


@pytest.fixture
def db(settings):
    with Database(settings.database_path) as database:
        yield database


# --- Fixtures saved directly through the stores ----------------------------------------

EXPRESS = Component(ref="e", name="express", version="4.0.0", purl_type="npm")
QS = Component(ref="q", name="qs", version="6.0.0", purl_type="npm")
TYPES = Component(ref="t", name="node", group="@types", version="20.0.0", purl_type="npm")
SBOM = Sbom(
    spec_version="1.5",
    generator="test",
    root_ref="root",
    components=[EXPRESS, QS, TYPES],
    edges=[
        DependencyEdge(source="root", target="e"),
        DependencyEdge(source="root", target="t"),
        DependencyEdge(source="e", target="q"),
    ],
    direct_source=DirectSource.GRAPH_INFERENCE,
)


def _profile(root, ecosystems=()):
    return RepositoryProfile(
        name="demo",
        root=str(root),
        total_files=1,
        total_bytes=1,
        git=GitInfo(is_repository=False),
        ecosystems=list(ecosystems),
    )


def _vuln(fid, component, severity, fix=None, fixed=()):
    return Finding(
        id=fid,
        kind=FindingKind.VULNERABILITY,
        title=f"{fid} in {component.name}",
        severity=severity,
        tool="osv-scanner",
        component_ref=component.ref,
        details=VulnerabilityDetails(
            vulnerability_id=fid,
            package=component.name,
            version=component.version,
            ecosystem="npm",
            recommended_fix=fix,
            fixed_versions=list(fixed),
        ),
    )


def _code(fid, severity, path="src/app.js"):
    return Finding(
        id=fid,
        kind=FindingKind.CODE,
        title=f"{fid} in {path}",
        severity=severity,
        tool="semgrep",
        path=path,
        start_line=1,
        details=CodeDetails(rule_id="js.eval", message="Avoid eval", cwe_ids=["CWE-95"]),
    )


def _change(fid, category, title="change"):
    return Finding(
        id=fid,
        kind=FindingKind.CHANGE,
        title=title,
        severity=Severity.MEDIUM,
        tool="git",
        details=ChangeDetails(category=category, commit="c" * 40, paths=[".env"]),
    )


def _store(db, profile, findings, *, sbom=SBOM, index=None, runs=(), warnings=()):
    repo_id = db.repositories.upsert(profile.root, profile.name)
    db.scans.create("scan1", repo_id, datetime.now(UTC), profile)
    if sbom is not None:
        db.sboms.save("scan1", sbom)
    db.findings.save("scan1", list(findings), [])
    if index is not None:
        db.code.save("scan1", index)
    db.scans.finish(
        "scan1",
        status=ScanStatus.PARTIAL,
        finished_at=datetime.now(UTC),
        tool_runs=list(runs),
        warnings=list(warnings),
        component_count=len(sbom.components) if sbom else 0,
        finding_count=len(findings),
    )
    return "scan1"


FINDINGS = [
    _vuln("V-LOW", QS, Severity.LOW),
    _vuln("V-CRIT", EXPRESS, Severity.CRITICAL, fix="4.0.9"),
    _vuln("V-HIGH", QS, Severity.HIGH, fix="6.1.0", fixed=("6.1.0",)),
    _vuln("V-HIGH2", QS, Severity.MEDIUM, fix="6.10.0", fixed=("6.10.0",)),
    _code("C-INFO", Severity.INFO),
    _change("G-SENS", ChangeCategory.SENSITIVE_FILE, "Sensitive file .env (still present)"),
]


def test_findings_are_sorted_and_summarized(db, settings, tmp_path):
    scan = _store(db, _profile(tmp_path / "gone"), FINDINGS)
    report = build_report(db, scan, settings)

    ids = [f.finding.id for f in report.findings]
    assert ids[0] == "V-CRIT"
    assert ids[-1] == "C-INFO"  # informational -> P4
    priorities = [f.risk.priority for f in report.findings]
    assert priorities == sorted(priorities, key=list(Priority).index)
    assert report.summary.total_findings == 6
    assert {c.severity: c.count for c in report.summary.by_severity}[Severity.CRITICAL] == 1
    assert sum(c.count for c in report.summary.by_priority) == 6
    assert report.summary.by_kind == {"vulnerability": 4, "code": 1, "change": 1}
    assert report.summary.components == 3
    assert report.summary.direct_dependencies == 2
    assert report.summary.files_indexed == 0
    assert "critical vulnerability in express" in report.summary.headline
    assert report.meta.repository == "demo"
    assert report.meta.source == str(tmp_path / "gone")
    assert report.meta.ai_used is False
    assert all(f.code == [] for f in report.findings)  # no index, missing root


def test_introduction_paths_and_remediation(db, settings, tmp_path):
    report = build_report(db, _store(db, _profile(tmp_path), FINDINGS), settings)
    by_id = {f.finding.id: f for f in report.findings}
    assert by_id["V-HIGH"].introduction_paths == [["express@4.0.0", "qs@6.0.0"]]
    assert "transitive dependency via express@4.0.0" in by_id["V-HIGH"].remediation
    assert by_id["V-CRIT"].remediation == "Upgrade express to 4.0.9 or later."
    assert "No fixed version of qs" in by_id["V-LOW"].remediation
    assert by_id["C-INFO"].remediation == "Fix the pattern flagged by js.eval (CWE-95): Avoid eval"
    assert "rotate any secrets" in by_id["G-SENS"].remediation


def test_packages_aggregate_vulnerabilities(db, settings, tmp_path):
    report = build_report(db, _store(db, _profile(tmp_path), FINDINGS), settings)
    express, qs = report.packages
    assert (express.package, express.direct, express.worst_severity) == (
        "express",
        True,
        Severity.CRITICAL,
    )
    assert express.used_in_code is None  # no code index
    assert (qs.vulnerability_count, qs.direct, qs.recommended_fix) == (3, False, "6.10.0")
    assert report.summary.vulnerable_packages == 2
    assert report.summary.vulnerable_packages_used_in_code == 0


def test_cap_adds_limitation(db, settings, tmp_path):
    report = build_report(db, _store(db, _profile(tmp_path), FINDINGS), settings, max_findings=2)
    assert len(report.findings) == 2
    assert report.summary.total_findings == 6
    assert report.limitations[0].startswith("4 lower-priority finding(s) omitted")


def test_limitations(db, settings, tmp_path):
    node = EcosystemProfile(
        ecosystem=Ecosystem.NODE,
        adapter="node",
        manifests=[
            ManifestFile(path="package.json", ecosystem=Ecosystem.NODE, kind=ManifestKind.MANIFEST)
        ],
    )
    runs = [
        ToolRunSummary(tool="cdxgen", status="success"),
        ToolRunSummary(tool="semgrep", status="not_found", error="semgrep missing"),
        ToolRunSummary(tool="git", status="skipped"),
    ]
    index = CodeIndex(
        files=[
            FileIndex(
                path="a.py",
                language=SourceLanguage.PYTHON,
                sha256="0" * 64,
                size=1,
                line_count=1,
            )
        ],
        skipped_files={"too-large": 2, "minified": 1},
    )
    warnings = [f"w{i}" for i in range(25)]
    scan = _store(db, _profile(tmp_path, [node]), [], index=index, runs=runs, warnings=warnings)
    report = build_report(db, scan, settings)
    text = "\n".join(report.limitations)
    assert "semgrep not_found: semgrep missing" in text
    assert "cdxgen" not in text
    assert "git skipped" not in text
    assert "Scan warning: w19" in text
    assert "Scan warning: w20" not in text
    assert "5 more scan warning(s)" in text
    assert "Exploitability was not assessed" in text
    assert "inferred from the dependency graph" in text
    assert "skipped 3 file(s) (minified 1, too-large 2)" in text
    assert "No lockfile found for node" in text
    assert report.summary.headline.startswith("No security findings")
    assert report.summary.files_indexed == 1
    assert report.packages == []


def test_without_sbom_or_index(db, settings, tmp_path):
    findings = [_vuln("V1", EXPRESS, Severity.HIGH, fix="4.1.0"), _code("C1", Severity.HIGH)]
    report = build_report(db, _store(db, _profile(tmp_path), findings, sbom=None), settings)
    text = "\n".join(report.limitations)
    assert "No SBOM was stored" in text
    assert "No code index" in text
    assert report.summary.components == 0
    (pkg,) = report.packages
    assert (pkg.package, pkg.direct, pkg.used_in_code) == ("express", None, None)
    assert all(f.introduction_paths == [] for f in report.findings)


def test_remote_source_and_unknown_scan(db, settings):
    root = settings.data_dir / "workspaces" / "abc" / "demo"
    report = build_report(db, _store(db, _profile(root), []), settings)
    assert report.meta.source == "remote clone of demo"
    with pytest.raises(ScanNotFoundError):
        build_report(db, "nope", settings)


def test_change_remediation_variants():
    removed = _change("g", ChangeCategory.SENSITIVE_FILE, "Sensitive file .env (since removed)")
    assert "remains in git history" in remediation(removed, [])
    ci = _change("g", ChangeCategory.CI_CONFIG)
    assert "CI configuration" in remediation(ci, [])
    lock = _change("g", ChangeCategory.LOCKFILE_ONLY)
    assert "lockfile" in remediation(lock, [])


def test_fixed_versions_only_remediation():
    finding = _vuln("V", QS, Severity.HIGH, fixed=("6.2.0", "7.0.1"))
    text = remediation(finding, [["express@4.0.0", "qs@6.0.0"]])
    assert text.startswith("Upgrade qs to a fixed release (6.2.0, 7.0.1).")
    assert "pin/override qs" in text


# --- End to end through the scan pipeline ----------------------------------------------


class FixtureGenerator(SbomGenerator):
    def __init__(self, content: bytes):
        super().__init__(ToolRunner())
        self.content = content

    def generate(self, repo_root, work_dir):
        bom = work_dir / "bom.json"
        bom.write_bytes(self.content)
        result = ToolResult(tool="cdxgen", args=[], status=ToolStatus.SUCCESS, exit_code=0)
        return SbomGeneration(result=result, bom_path=bom)


def test_pipeline_scan_report_includes_code_context(db, settings, make_repo):
    root = make_repo(
        {
            "package.json": '{"dependencies": {"express": "4", "lodash": "4"}}',
            "app.js": (
                "const _ = require('lodash');\n"
                "const express = require('express');\n"
                "const app = express();\n"
                "app.get('/t', (req, res) => res.send(_.template(req.query.t)()));\n"
                "app.listen(3000);\n"
            ),
        }
    )
    osv_output = (FIXTURES / "osv" / "node.osv.json").read_bytes()

    class SbomAwareOsv(StubAnalyzer):
        def scan(self, repo_root, work_dir, sbom, raw_sbom, excluded=frozenset()):
            return analysis("osv-scanner", parse_osv_output(osv_output, sbom)[0])

    pipeline = ScanPipeline(
        db,
        settings,
        sbom_generator=FixtureGenerator((FIXTURES / "sbom" / "node-express.cdx.json").read_bytes()),
        osv_scanner=SbomAwareOsv(analysis("osv-scanner")),
        semgrep_scanner=StubAnalyzer(analysis("semgrep")),
        change_analyzer=StubAnalyzer(analysis("git", status="skipped")),
    )
    outcome = pipeline.run(root)
    report = build_report(db, outcome.record.id, settings)

    assert report.summary.files_indexed == 1
    assert report.entry_points
    lodash = next(p for p in report.packages if p.package == "lodash")
    assert report.packages[0] is lodash  # direct and used in code sorts first
    assert lodash.direct is True
    assert lodash.used_in_code is True
    assert report.summary.vulnerable_packages_used_in_code == 1
    top = report.findings[0]
    assert top.finding.component_ref == "pkg:npm/lodash@4.17.20"
    unlinked = next(f for f in report.findings if f.finding.component_ref is None)
    assert unlinked.risk.priority is not Priority.P1  # low confidence caps at P2
    assert "lodash that the code calls" in report.summary.headline
    assert top.code
    assert top.code[0].path == "app.js"
    assert "that the code calls" in top.risk.summary

    without_code = build_report(db, outcome.record.id, settings, include_code=False)
    assert all(f.code == [] for f in without_code.findings)

import json
from pathlib import Path

import pytest

from guardian.analysis.cyclonedx import parse_cyclonedx
from guardian.analysis.osv import OsvScanner, parse_osv_output, version_key
from guardian.core.models import EvidenceKind, FindingKind, Severity
from guardian.execution.results import ToolResult, ToolStatus
from guardian.execution.runner import ToolRunner

FIXTURES = Path(__file__).parents[1] / "fixtures"
OSV_OUTPUT = (FIXTURES / "osv" / "node.osv.json").read_bytes()


@pytest.fixture
def sbom():
    raw = (FIXTURES / "sbom" / "node-express.cdx.json").read_bytes()
    return parse_cyclonedx(raw, repo_root=Path("/repo"), manifests=set())


@pytest.fixture
def findings(sbom):
    found, _ = parse_osv_output(OSV_OUTPUT, sbom)
    return {f.details.vulnerability_id: f for f in found}


def test_one_finding_per_alias_group(findings):
    assert sorted(findings) == [
        "CVE-2020-28500",
        "CVE-2021-23337",
        "CVE-2024-45296",
        "CVE-2024-47764",
        "OSV-2099-1",
    ]


def test_vulnerability_details(findings):
    f = findings["CVE-2021-23337"]
    assert f.kind is FindingKind.VULNERABILITY
    assert f.severity is Severity.HIGH
    assert f.title == "CVE-2021-23337 in lodash@4.17.20"
    d = f.details
    assert d.summary == "Command Injection in lodash"
    assert d.cvss_score == 7.2
    assert d.aliases == ["GHSA-35jh-r3h4-6jhm"]
    assert d.cwe_ids == ["CWE-77", "CWE-94"]
    assert d.fixed_versions == ["4.17.21"]  # lodash-es range ignored
    assert d.recommended_fix == "4.17.21"
    assert d.purl == "pkg:npm/lodash@4.17.20"  # osv-scanner's ?source= qualifier stripped
    assert d.published is not None
    assert d.references == ["https://nvd.nist.gov/vuln/detail/CVE-2021-23337"]


def test_maps_to_sbom_component_and_carries_evidence(findings):
    f = findings["CVE-2021-23337"]
    assert f.component_ref == "pkg:npm/lodash@4.17.20"
    kinds = [e.kind for e in f.evidence]
    assert kinds[:2] == [EvidenceKind.TOOL_MATCH, EvidenceKind.ADVISORY]
    assert f.evidence[1].url == "https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm"


def test_severity_sources(findings):
    assert findings["CVE-2020-28500"].severity is Severity.MEDIUM  # from CVSS 5.3
    cookie = findings["CVE-2024-47764"]
    assert cookie.severity is Severity.LOW  # no score: advisory's own label
    assert cookie.details.cvss_score is None
    assert findings["OSV-2099-1"].severity is Severity.UNKNOWN


def test_recommended_fix_uses_the_range_containing_the_version(findings):
    d = findings["CVE-2024-45296"].details
    assert d.fixed_versions == ["0.1.10", "1.9.0", "8.0.0"]
    assert d.recommended_fix == "0.1.10"
    assert findings["OSV-2099-1"].details.recommended_fix is None


def test_unmatched_packages_warn(sbom):
    _, warnings = parse_osv_output(OSV_OUTPUT, sbom)
    assert warnings == ["3 vulnerable package(s) reported by OSV-Scanner are not in the SBOM"]


def test_without_sbom_nothing_is_mapped_and_no_warning():
    found, warnings = parse_osv_output(OSV_OUTPUT, None)
    assert all(f.component_ref is None for f in found)
    assert warnings == []


def test_ids_are_stable_and_ordering_is_by_severity(sbom):
    first, _ = parse_osv_output(OSV_OUTPUT, sbom)
    second, _ = parse_osv_output(OSV_OUTPUT, sbom)
    assert [f.id for f in first] == [f.id for f in second]
    ranks = [f.severity.rank for f in first]
    assert ranks == sorted(ranks, reverse=True)


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        ("1.9.0", "1.10.0"),
        ("1.0.0-beta", "1.0.0"),
        ("1.0.0", "1.0.0.1"),
        ("0.1.7", "0.1.10"),
        ("2.0.0rc1", "2.0.0"),
    ],
)
def test_version_ordering(lower, higher):
    assert version_key(lower) < version_key(higher)


class FakeRunner(ToolRunner):
    def __init__(self, output: bytes | None, exit_code: int = 1):
        super().__init__()
        self.output, self.exit_code, self.args = output, exit_code, None

    def run(self, tool, args, *, cwd, timeout_seconds=None, env=None):
        self.args = list(args)
        if self.output is not None:
            Path(args[args.index("--output-file") + 1]).write_bytes(self.output)
        status = ToolStatus.SUCCESS if self.exit_code == 0 else ToolStatus.FAILED
        return ToolResult(tool=tool, args=list(args), status=status, exit_code=self.exit_code)


def test_scanner_uses_the_sbom_when_available(tmp_path, sbom):
    runner = FakeRunner(OSV_OUTPUT, exit_code=1)  # 1 = vulnerabilities found
    result = OsvScanner(runner).scan(tmp_path, tmp_path, sbom, b"{}")
    assert result.tool_run.status == "success"
    assert len(result.findings) == 5
    assert "--lockfile" in runner.args
    assert runner.args[runner.args.index("--lockfile") + 1].endswith("guardian.cdx.json")
    assert "--no-resolve" in runner.args
    assert "--no-call-analysis=all" in runner.args


def test_scanner_falls_back_to_recursive_source_scan(tmp_path):
    runner = FakeRunner(json.dumps({"results": []}).encode(), exit_code=0)
    result = OsvScanner(runner).scan(tmp_path, tmp_path, None, None, frozenset({"node_modules"}))
    assert result.tool_run.status == "success"
    assert "--recursive" in runner.args
    assert runner.args[runner.args.index("--x-exclude") + 1] == "node_modules"
    assert runner.args[-1] == str(tmp_path)


def test_scanner_reports_failures(tmp_path):
    missing = OsvScanner(FakeRunner(None, exit_code=127)).scan(tmp_path, tmp_path, None, None)
    assert missing.tool_run.status == "failed"
    garbage = OsvScanner(FakeRunner(b"not json", exit_code=1)).scan(tmp_path, tmp_path, None, None)
    assert garbage.tool_run.status == "failed"
    assert "Unreadable OSV-Scanner output" in garbage.tool_run.error

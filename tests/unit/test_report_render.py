import json
import re
from datetime import UTC, datetime
from html.parser import HTMLParser

import pytest

from guardian.core.models import (
    RISK_WEIGHTS,
    ChangeCategory,
    ChangeDetails,
    CodeDetails,
    Confidence,
    EntryPoint,
    EntryPointKind,
    Evidence,
    EvidenceKind,
    Finding,
    FindingKind,
    Priority,
    RiskAssessment,
    RiskFactor,
    RiskFactorName,
    ScanRecord,
    ScanStatus,
    Severity,
    ToolRunSummary,
    VulnerabilityDetails,
)
from guardian.indexing.code_retriever import CodeSnippet
from guardian.reporting.html_report import render_html, script_safe_json
from guardian.reporting.json_report import render_json
from guardian.reporting.markdown_report import (
    REVIEW_CHECKLIST,
    code_fence,
    md_code,
    md_text,
    md_url,
    render_markdown,
)
from guardian.reporting.models import (
    PackageRisk,
    PriorityCount,
    ReportData,
    ReportFinding,
    ReportFormat,
    ReportMeta,
    ReportSummary,
    SeverityCount,
)
from guardian.reporting.render import report_basename, write_reports

HOSTILE = "</script><img src=x onerror=alert(1)> [click](https://evil.example) ![i](https://t.example/p.png) @admin #12 *bold* <!--"
TICKS = "x = ```` ` `` y"
NOW = datetime(2026, 11, 24, 12, 0, tzinfo=UTC)


def _risk(finding_id: str, priority: Priority, score: float | None) -> RiskAssessment:
    values = {
        RiskFactorName.SEVERITY: 0.9,
        RiskFactorName.EXPOSURE: 0.6,
        RiskFactorName.EXPLOITABILITY: None,
        RiskFactorName.REACHABILITY: 1.0,
        RiskFactorName.FIX: 0.5,
    }
    return RiskAssessment(
        finding_id=finding_id,
        score=score,
        known_weight=0.8,
        confidence=Confidence.MEDIUM,
        priority=priority,
        factors=[
            RiskFactor(name=n, weight=w, value=values[n], rationale=f"{n.value} because {HOSTILE}")
            for n, w in RISK_WEIGHTS.items()
        ],
        summary=f"Why: {HOSTILE}",
    )


def make_report(*, findings: int = 3, repo: str = "demo/app") -> ReportData:
    vuln = Finding(
        id="vuln0001",
        kind=FindingKind.VULNERABILITY,
        title=f"CVE-2021-23337 in lodash {HOSTILE}",
        severity=Severity.HIGH,
        tool="osv-scanner",
        component_ref="pkg:npm/lodash@4.17.20",
        details=VulnerabilityDetails(
            vulnerability_id="CVE-2021-23337",
            summary=HOSTILE,
            package="lodash",
            version="4.17.20",
            ecosystem="npm",
            cvss_score=7.2,
            fixed_versions=["4.17.21"],
            recommended_fix="4.17.21",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-23337", "javascript:alert(1)"],
        ),
        evidence=[
            Evidence(
                kind=EvidenceKind.ADVISORY,
                tool="osv",
                summary=HOSTILE,
                url="javascript:alert(document.cookie)",
            ),
            Evidence(
                kind=EvidenceKind.MANIFEST,
                tool="cdxgen",
                summary="declared",
                path="package.json",
                line=3,
                url="https://osv.dev/CVE-2021-23337",
            ),
        ],
    )
    code = Finding(
        id="code0001",
        kind=FindingKind.CODE,
        title="eval of user input",
        severity=Severity.CRITICAL,
        tool="semgrep",
        path="app.js",
        start_line=2,
        end_line=2,
        details=CodeDetails(rule_id="js.eval", message=f"Do not eval {HOSTILE}"),
    )
    change = Finding(
        id="change01",
        kind=FindingKind.CHANGE,
        title="CI config changed",
        severity=Severity.LOW,
        tool="git",
        details=ChangeDetails(
            category=ChangeCategory.CI_CONFIG,
            commit="abcdef1234567890",
            author=HOSTILE,
            paths=[".github/workflows/ci.yml"],
        ),
    )
    snippet = CodeSnippet(
        path="app.js",
        start_line=1,
        end_line=3,
        text=f"const a = 1;\neval(req.query.x) // {TICKS}\n{HOSTILE}",
        redactions=1,
    )
    rows = [
        ReportFinding(
            finding=code,
            risk=_risk("code0001", Priority.P1, 91.0),
            code=[snippet],
            remediation=f"Remove eval. {HOSTILE}",
        ),
        ReportFinding(
            finding=vuln,
            risk=_risk("vuln0001", Priority.P2, 70.5),
            introduction_paths=[["express@4.17.1", f"lodash@4.17.20{HOSTILE}"]],
            remediation="Upgrade lodash to 4.17.21",
        ),
        ReportFinding(
            finding=change,
            risk=_risk("change01", Priority.P4, None),
            remediation="Review the workflow change.",
        ),
    ][:findings]
    scan = ScanRecord(
        id="0123456789abcdef0123",
        repository_name=repo,
        repository_root="/tmp/repo",
        status=ScanStatus.COMPLETED,
        started_at=NOW,
        git_commit="feedface" * 5,
        warnings=[f"warn {HOSTILE}"],
    )
    return ReportData(
        meta=ReportMeta(
            guardian_version="0.1.0",
            generated_at=NOW,
            repository=repo,
            source=f"github.com/{repo}",
            scan=scan,
        ),
        summary=ReportSummary(
            headline=f"Headline {HOSTILE}",
            total_findings=10,
            by_severity=[SeverityCount(severity=Severity.CRITICAL, count=1)],
            by_priority=[PriorityCount(priority=p, count=1) for p in Priority],
            by_kind={"code": 1, "vulnerability": 1, "change": 1},
            components=7,
            direct_dependencies=2,
            vulnerable_packages=1,
            vulnerable_packages_used_in_code=1,
            files_indexed=4,
            entry_points=1,
        ),
        findings=rows,
        packages=[
            PackageRisk(
                package=f"lodash{HOSTILE}",
                version="4.17.20",
                ecosystem="npm",
                direct=True,
                used_in_code=None,
                vulnerability_count=1,
                worst_severity=Severity.HIGH,
                recommended_fix="4.17.21",
            )
        ],
        entry_points=[
            EntryPoint(path="app.js", line=1, kind=EntryPointKind.HTTP_ROUTE, detail=HOSTILE)
        ],
        tool_runs=[ToolRunSummary(tool="semgrep", status="failed", error=HOSTILE)],
        limitations=[f"limit {HOSTILE}"],
    )


# --- JSON ------------------------------------------------------------------------------


def test_json_round_trips_and_is_stable():
    report = make_report()
    text = render_json(report)
    data = json.loads(text)
    assert data["meta"]["schema_version"] == "2"
    assert "remediation" not in data
    assert list(data)[:2] == ["meta", "summary"]
    assert ReportData.model_validate(data) == report
    assert render_json(report) == text
    assert text.endswith("\n")


# --- Markdown --------------------------------------------------------------------------


def test_md_text_neutralizes_markdown_and_html():
    out = md_text(HOSTILE + "\nnext line")
    assert "\n" not in out
    # Every character that could start markup is backslash-escaped.
    assert re.search(r"(?<!\\)[<>\[\]!*@#`]", out) is None
    assert "\\<img" in out
    assert "\\[click\\]\\(https://evil.example\\)" in out


def test_md_code_and_fence_outgrow_backtick_runs():
    assert md_code("a ``` b") == "````a ``` b````"
    assert md_code("`x`") == "`` `x` ``"
    assert md_code("a|b", in_table=True) == "`a\\|b`"
    assert code_fence("plain") == "```"
    assert code_fence(TICKS) == "`````"


def test_md_url_only_links_plain_https():
    assert md_url("https://osv.dev/x") == "<https://osv.dev/x>"
    assert md_url("javascript:alert(1)") == "`javascript:alert(1)`"
    assert md_url("https://a.example/<script>") == "`https://a.example/<script>`"
    assert md_url(None) == ""


def test_markdown_report_structure():
    md = render_markdown(make_report())
    assert md.startswith("# Guardian security report: demo/app\n")
    assert "| Scan | `0123456789abcdef0123` |" in md
    assert "### P1: act now (1)" in md
    assert "### P2: schedule soon (1)" in md
    assert "### P3" not in md
    assert md.index("### P1") < md.index("### P2") < md.index("### P4")
    assert md.count(REVIEW_CHECKLIST) == 3
    assert "| exploitability | 0.20 | unknown |" in md
    assert "| severity | 0.35 | 0.90 |" in md
    assert "Showing the 3 highest-priority of 10 findings." in md
    assert "`express@4.17.1` → " in md
    assert "<https://osv.dev/CVE-2021-23337>" in md
    assert "`javascript:alert(document.cookie)`" in md
    assert "## Tool runs" in md
    assert "## Limitations" in md
    assert "Risk n/a" not in md  # score shown as "**Risk** n/a"
    assert "**Risk** n/a" in md


def test_markdown_code_block_is_fenced_and_numbered():
    md = render_markdown(make_report())
    fence = "`````"
    start = md.index(fence + "javascript\n")
    end = md.index("\n" + fence + "\n", start)
    body = md[start + len(fence) + len("javascript\n") : end]
    assert body.splitlines()[0] == "1 | const a = 1;"
    assert body.splitlines()[1].startswith("2 | eval(req.query.x)")
    assert "1 secret(s) redacted" in md


def test_markdown_never_contains_raw_hostile_markup_outside_code():
    md = render_markdown(make_report())
    # Remove fenced code blocks and inline code spans, then nothing hostile may remain.
    prose = re.sub(r"(`{3,})[^\n]*\n.*?\n\1\n", "", md, flags=re.DOTALL)
    prose = re.sub(r"(`+)(?!`).+?(?<!`)\1(?!`)", "", prose)
    prose = re.sub(r"<https://[^\s<>]+>", "", prose)  # our own autolinks
    assert re.search(r"(?<!\\)<", prose) is None
    assert re.search(r"(?<!\\)\]\(", prose) is None


# --- HTML ------------------------------------------------------------------------------


class _Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []
        self.scripts: list[str] = []
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))
        self._in_script = tag == "script"

    def handle_endtag(self, tag):
        self._in_script = False

    def handle_data(self, data):
        if self._in_script:
            self.scripts.append(data)


def _embedded(page: str) -> dict:
    match = re.search(
        r'<script id="report-data" type="application/json">(.*?)</script>', page, re.DOTALL
    )
    assert match
    return json.loads(match.group(1))


def test_html_embeds_data_safely():
    report = make_report()
    page = render_html(report)
    data = _embedded(page)
    assert ReportData.model_validate(data) == report
    # Hostile text never appears as markup: only the template's own tags exist.
    parser = _Collector()
    parser.feed(page)
    tags = {t for t, _ in parser.tags}
    assert "img" not in tags
    assert sum(1 for t, _ in parser.tags if t == "script") == 2
    assert page.count("</script>") == 2
    assert "onerror=alert" not in page.replace("onerror=alert(1)\\u003e", "")
    assert "\\u003c/script\\u003e" in page


def test_html_title_is_escaped_and_placeholders_are_single_pass():
    report = make_report(repo='<b>"x"</b>/*__REPORT_DATA__*/__SCRIPT_HASH__')
    page = render_html(report)
    title = re.search(r"<title>(.*?)</title>", page, re.DOTALL).group(1)
    assert "&lt;b&gt;&quot;x&quot;&lt;/b&gt;/*__REPORT_DATA__*/__SCRIPT_HASH__" in title
    assert "__TITLE__" not in page
    assert _embedded(page)["meta"]["repository"].startswith("<b>")


def test_html_csp_pins_the_page_script():
    page = render_html(make_report())
    csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', page).group(1)
    assert "default-src 'none'" in csp
    assert "'unsafe-inline'" not in csp.split("script-src", 1)[1].split(";", 1)[0]
    script = re.search(r'<script id="app">(.*?)</script>', page, re.DOTALL).group(1)
    import base64
    import hashlib

    digest = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
    assert f"script-src 'sha256-{digest}'" in csp


def test_html_has_no_external_resources_except_fonts():
    page = render_html(make_report())
    parser = _Collector()
    parser.feed(page)
    for tag, attrs in parser.tags:
        for attr in ("src", "href"):
            value = attrs.get(attr)
            if value and tag in {"script", "link", "img", "iframe"}:
                assert value.startswith(
                    ("https://fonts.googleapis.com", "https://fonts.gstatic.com")
                )
    assert "<script src" not in page
    # The page renders untrusted values only through textContent.
    script = "".join(parser.scripts)
    assert "innerHTML" not in script
    assert "insertAdjacentHTML" not in script
    assert "document.write" not in script


def test_script_safe_json_escapes_breakouts():
    text = script_safe_json({"a": "</script><!-- & \u2028"})
    assert "<" not in text
    assert ">" not in text
    assert "&" not in text
    assert "\u2028" not in text
    assert json.loads(text) == {"a": "</script><!-- & \u2028"}


def test_html_with_no_findings():
    report = make_report(findings=0)
    page = render_html(report)
    assert _embedded(page)["findings"] == []


# --- write_reports ---------------------------------------------------------------------


def test_write_reports_names_and_order(tmp_path):
    report = make_report(repo="../../etc/passwd <x>")
    out = tmp_path / "nested" / "out"
    paths = write_reports(
        report, out, [ReportFormat.JSON, ReportFormat.HTML, ReportFormat.MARKDOWN]
    )
    base = "guardian-report-etc-passwd-x-0123456789ab"
    assert [p.name for p in paths] == [f"{base}.json", f"{base}.html", f"{base}.md"]
    assert all(p.parent == out and p.is_file() for p in paths)
    assert json.loads(paths[0].read_text(encoding="utf-8"))["meta"]["scan"]["id"].startswith("0123")
    assert b"\r\n" not in paths[2].read_bytes()


@pytest.mark.parametrize(
    ("repo", "expected"),
    [("demo/app", "demo-app"), ("...", "repository"), ("ok_name-1.2", "ok_name-1.2")],
)
def test_report_basename_sanitizes(repo, expected):
    assert report_basename(make_report(repo=repo)) == f"guardian-report-{expected}-0123456789ab"


def test_write_reports_deduplicates(tmp_path):
    paths = write_reports(make_report(), tmp_path, ["md", ReportFormat.MARKDOWN])
    assert len(paths) == 1

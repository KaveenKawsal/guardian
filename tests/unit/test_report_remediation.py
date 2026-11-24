"""The report's Remediation section (schema 2) over a seeded database."""

import json
import re
from datetime import date

import pytest
from remediation_fakes import T0, make_scan, sbom_with, vuln

from guardian.core.config import GuardianSettings
from guardian.core.models import Evidence, EvidenceKind, Priority
from guardian.core.remediation_models import (
    CaseStatus,
    ComponentChange,
    DecisionType,
    DeclineReason,
    HumanDecision,
    RemediationActionType,
    RemediationCandidate,
    RemediationCase,
    RemediationPlan,
    SbomDiff,
    SemverJump,
    StepStatus,
    ValidationRun,
    ValidationStep,
    VerificationResult,
    VerificationStatus,
    candidate_id_for,
    case_id_for,
    fingerprint_for,
)
from guardian.investigation.models import InvestigationRun, InvestigatorReport
from guardian.reporting.html_report import render_html
from guardian.reporting.json_report import render_json
from guardian.reporting.markdown_report import KNOWN_CONFLICT_NOTE, render_markdown
from guardian.reporting.models import REPORT_SCHEMA_VERSION, ReportData
from guardian.reporting.remediation_report import ai_statements, jira_url
from guardian.reporting.report_data import build_report
from guardian.storage.database import Database

HOSTILE = "<script>alert('x')</script> [link](https://evil.example) @admin"
ROOT = "/repos/app"
PR_URL = "https://github.com/acme/app/pull/7"
JIRA = "https://acme.atlassian.net"


@pytest.fixture
def settings(tmp_path):
    return GuardianSettings(_env_file=None, data_dir=tmp_path / "data", jira_base_url=JIRA)


@pytest.fixture
def db(settings):
    settings.data_dir.mkdir(parents=True)
    with Database(settings.database_path) as database:
        yield database


def _evidence(text: str) -> Evidence:
    return Evidence(kind=EvidenceKind.ADVISORY, tool="osv-scanner", summary=text, url=PR_URL)


def _case(db, key: str, finding_ids: list[str], title: str, priority=Priority.P1):
    fp = fingerprint_for(ROOT, f"pkg:npm/{key}", key)
    case = RemediationCase(
        id=case_id_for(fp),
        fingerprint=fp,
        scan_id="before",
        repository_root=ROOT,
        finding_ids=finding_ids,
        title=title,
        priority=priority,
        created_at=T0,
        updated_at=T0,
    )
    return db.remediation.create(case)


def _walk(db, case, *states):
    for state in states:
        db.remediation.update_status(case.id, state)


def _candidates(db, case, package: str, llm: bool = False):
    cands = [
        RemediationCandidate(
            id=candidate_id_for(case.fingerprint, RemediationActionType.UPGRADE, package, v),
            case_id=case.id,
            finding_ids=case.finding_ids,
            action_type=RemediationActionType.UPGRADE,
            component=f"pkg:npm/{package}",
            from_version="1.0.0",
            to_version=v,
            fixes_finding_ids=case.finding_ids,
            semver_jump=jump,
            compatibility_notes=["major bump: review breaking changes"] if jump == "major" else [],
            rollback="git revert HEAD",
            expected_risk_reduction=42.0,
        )
        for v, jump in (("1.0.1", SemverJump.PATCH), ("2.0.0", SemverJump.MAJOR))
    ]
    db.remediation.save_candidates(case.id, cands)
    plan = RemediationPlan(
        case_id=case.id,
        chosen_candidate_id=cands[0].id,
        alternatives=[cands[1].id],
        rationale=f"AI says patch is safest {HOSTILE}" if llm else "lowest semver jump",
        confidence="medium" if llm else "high",
        llm_provider="groq" if llm else None,
        llm_model="llama-3.3-70b" if llm else None,
        source="inferred" if llm else "verified",
        decided_by="llm" if llm else "deterministic",
    )
    db.remediation.save_plan(plan)
    return cands


def _decide(db, case, kind, **kwargs):
    db.remediation.save_decision(
        HumanDecision(
            case_id=case.id,
            decision=kind,
            actor_id="acc-1",
            actor_display="Alice Approver",
            channel=kwargs.pop("channel", "jira"),
            decided_at=T0,
            **kwargs,
        )
    )


def _validation(db, case, test_status, *, known_conflict=False):
    db.remediation.save_validation(
        ValidationRun(
            case_id=case.id,
            branch=f"guardian/fix-{case.id}",
            worktree_path="/tmp/wt",
            sandbox="docker",
            steps=[
                ValidationStep(name="install", status=StepStatus.PASSED, exit_code=0),
                ValidationStep(
                    name="test",
                    status=test_status,
                    exit_code=0 if test_status is StepStatus.PASSED else 1,
                    duration_seconds=12.5,
                    detail="rsn.unit.test.ts failed" if known_conflict else None,
                    known_conflict=known_conflict,
                ),
            ],
            tests_discovered=10,
            tests_passed=9 if known_conflict else 10,
            tests_failed=1 if known_conflict else 0,
            started_at=T0,
        )
    )


def _verification(db, case, status, resolved, still, risk_after):
    db.remediation.save_verification(
        VerificationResult(
            case_id=case.id,
            before_scan_id="before",
            after_scan_id="after",
            target_findings_resolved=resolved,
            findings_still_present=still,
            sbom_diff=SbomDiff(
                changed=[
                    ComponentChange(purl_base="pkg:npm/lodash", from_version="1", to_version="2")
                ]
            ),
            risk_before=80.0,
            risk_after=risk_after,
            status=status,
            confidence="high",
            reasons=[f"rescan {status.value}"],
        )
    )


def _investigation(db, case):
    reports = [
        InvestigatorReport(
            agent="dependency",
            subject_kind="case",
            subject_id=case.id,
            status="ok",
            provider="groq",
            model="llama-3.3-70b",
            assessment={
                "how_it_enters": {"text": "Direct dependency of the API", "evidence_refs": ["f4"]},
                "scope_assessment": "prod",
                "scope_reasons": [],
                "blast_radius": {"text": f"Login route {HOSTILE}", "evidence_refs": []},
                "source": "inferred",
            },
        ),
        InvestigatorReport(
            agent="correlator",
            subject_kind="case",
            subject_id=case.id,
            status="ok",
            provider="gemini",
            model="gemini-2.5-pro",
            assessment={
                "assessment": {"text": "Likely exploitable", "evidence_refs": ["f4"]},
                "confidence": "medium",
                "recommendation": None,
                "source": "inferred",
            },
        ),
        InvestigatorReport(  # no AI output: left out of the report
            agent="vulnerability",
            subject_kind="finding",
            subject_id="f4",
            status="ai_unavailable",
            source="verified",
        ),
    ]
    run = InvestigationRun(id="run-1", scan_id="before", started_at=T0, status="completed")
    db.investigations.save_run(run, reports)


def seed(db) -> dict[str, RemediationCase]:
    findings = [vuln(f"f{i}", package=f"pkg{i}") for i in range(1, 6)]
    findings[0] = findings[0].model_copy(update={"evidence": [_evidence(f"advisory {HOSTILE}")]})
    make_scan(db, "before", ROOT, findings=findings, sbom=sbom_with("pkg:npm/pkg1@1.0.0"))
    make_scan(db, "other", "/repos/other", findings=[vuln("zz", package="zz")])

    verified = _case(db, "a", ["f1"], f"Verified fix {HOSTILE}")
    _candidates(db, verified, "pkg1")
    db.remediation.link_jira(verified.id, "SEC-1")
    _walk(db, verified, CaseStatus.AWAITING_DECISION)
    _decide(db, verified, DecisionType.ACCEPT, justification=HOSTILE)
    _walk(db, verified, CaseStatus.APPROVED, CaseStatus.APPLYING, CaseStatus.VALIDATING)
    _validation(db, verified, StepStatus.PASSED)
    _verification(db, verified, VerificationStatus.VERIFIED, ["f1"], [], 0.0)
    _walk(db, verified, CaseStatus.VERIFIED)
    db.audit.append(verified.id, "pr:opened", "guardian", {"url": PR_URL})

    failed = _case(db, "b", ["f2"], "Conflicting fix", Priority.P2)
    _candidates(db, failed, "pkg2")
    _walk(db, failed, CaseStatus.AWAITING_DECISION)
    _decide(db, failed, DecisionType.ACCEPT, channel="cli")
    _walk(db, failed, CaseStatus.APPROVED, CaseStatus.APPLYING, CaseStatus.VALIDATING)
    _validation(db, failed, StepStatus.FAILED, known_conflict=True)
    _verification(db, failed, VerificationStatus.FAILED, [], ["f2"], 80.0)
    _walk(db, failed, CaseStatus.VALIDATION_FAILED)

    declined = _case(db, "c", ["f3"], "Accepted risk", Priority.P3)
    _candidates(db, declined, "pkg3")
    _walk(db, declined, CaseStatus.AWAITING_DECISION)
    _decide(
        db,
        declined,
        DecisionType.DECLINE,
        decline_reason=DeclineReason.ACCEPTED_RISK,
        risk_acceptance_expires=date(2026, 1, 31),
        justification=f"Behind VPN {HOSTILE}",
    )
    _walk(db, declined, CaseStatus.DECLINED)

    ai = _case(db, "d", ["f4"], "AI planned", Priority.P1)
    _candidates(db, ai, "pkg4", llm=True)
    _walk(db, ai, CaseStatus.AWAITING_DECISION)
    _investigation(db, ai)
    return {"verified": verified, "failed": failed, "declined": declined, "ai": ai}


@pytest.fixture
def report(db, settings) -> ReportData:
    seed(db)
    return build_report(db, "before", settings)


def _cases(report: ReportData) -> dict[str, object]:
    assert report.remediation is not None
    return {c.case.title.split(" ")[0]: c for c in report.remediation.cases}


def test_section_collects_each_case_state(report):
    section = report.remediation
    assert section is not None
    assert [c.case.priority for c in section.cases] == [
        Priority.P1,
        Priority.P1,
        Priority.P2,
        Priority.P3,
    ]
    assert {c.case.status for c in section.cases} == {
        CaseStatus.VERIFIED,
        CaseStatus.AWAITING_DECISION,
        CaseStatus.VALIDATION_FAILED,
        CaseStatus.DECLINED,
    }
    assert section.audit_chain.ok
    assert section.audit_chain.events > 10
    assert report.meta.schema_version == "2" == REPORT_SCHEMA_VERSION
    assert report.meta.ai_used

    by = _cases(report)
    verified = by["Verified"]
    assert verified.verdict is VerificationStatus.VERIFIED
    assert (verified.risk_before, verified.risk_after) == (80.0, 0.0)
    assert verified.pull_request_url == PR_URL
    assert verified.jira_url == f"{JIRA}/browse/SEC-1"
    assert verified.decisions[0].jira_url == f"{JIRA}/browse/SEC-1"
    assert verified.findings[0].evidence
    assert verified.recommended is not None
    assert len(verified.alternatives) == 1
    assert any(e.event == "pr:opened" for e in verified.audit)
    assert not verified.investigations

    failed = by["Conflicting"]
    assert failed.validations[0].steps[1].known_conflict
    assert failed.decisions[0].jira_url is None  # decided on the CLI

    declined = by["Accepted"]
    assert declined.accepted_risk is not None
    assert declined.accepted_risk.expired  # 2026-01-31 is before the report date
    assert declined.verdict is None
    assert declined.risk_before is not None  # from the scan's own risk scores

    ai = by["AI"]
    assert ai.plan is not None
    assert ai.plan.decided_by == "llm"
    assert [i.agent for i in ai.investigations] == ["dependency", "correlator"]
    assert ai.investigations[0].source == "inferred"
    assert ai.investigations[0].statements[0].evidence_refs == ["f4"]


def test_other_scans_cases_are_not_included(db, settings):
    seed(db)
    report = build_report(db, "other", settings)
    assert report.remediation is None


def test_verified_rescan_includes_case(db, settings):
    seed(db)
    make_scan(db, "after", ROOT, findings=[])
    report = build_report(db, "after", settings)
    assert report.remediation is not None
    titles = [c.case.title for c in report.remediation.cases]
    assert titles == [f"Verified fix {HOSTILE}", "Conflicting fix"]
    # findings no longer in the rescan come from the case's own scan
    assert report.remediation.cases[0].findings[0].id == "f1"


def test_broken_audit_chain_is_reported(db, settings):
    seed(db)
    db.conn.execute("DROP TRIGGER IF EXISTS audit_events_no_update")
    for (name,) in db.conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'audit_events'"
    ).fetchall():
        db.conn.execute(f"DROP TRIGGER {name}")
    db.conn.execute("UPDATE audit_events SET actor = 'mallory' WHERE id = 2")
    db.conn.commit()
    report = build_report(db, "before", settings)
    assert report.remediation is not None
    assert not report.remediation.audit_chain.ok
    assert "BROKEN" in render_markdown(report)


def test_markdown_section(report):
    md = render_markdown(report)
    assert "## Remediation" in md
    assert "| Case | Title | Priority | Status | Verdict | Risk before → after |" in md
    assert "80 → 0" in md
    assert "#### Original finding(s) (verified)" in md
    assert "#### AI investigation" in md
    assert "> AI inference: **Dependency Investigator**" in md
    assert "> - AI inference: How it enters: Direct dependency of the API" in md
    assert "Plan source: AI (groq / llama-3.3-70b)" in md
    assert "> AI inference: AI says patch is safest" in md
    assert "Plan source: deterministic (verified)" in md
    assert KNOWN_CONFLICT_NOTE in md
    assert "2026-01-31 EXPIRED" in md
    assert "**EXPIRED**" in md
    assert f"<{JIRA}/browse/SEC-1>" in md
    assert f"<{PR_URL}>" in md
    assert "#### Audit trail" in md
    assert "intact (" in md
    assert "pr:opened" in md
    # hostile text never forms HTML, links or mentions
    assert "<script>" not in md
    assert "](https://evil.example)" not in md
    assert " @admin" not in md


def test_json_section_round_trips(report):
    text = render_json(report)
    payload = json.loads(text)
    assert payload["meta"]["schema_version"] == "2"
    cases = payload["remediation"]["cases"]
    assert len(cases) == 4
    assert PR_URL in [c["pull_request_url"] for c in cases]
    assert payload["remediation"]["audit_chain"]["ok"] is True
    assert ReportData.model_validate(payload) == report


def test_html_section_is_escaped_and_distinct(report):
    page = render_html(report)
    assert 'id="remediation-section"' in page
    assert "tag ai" in page
    assert "tag verified" in page
    assert "fix conflicts with intentional challenge code" in page
    assert "<script>alert" not in page
    data = re.search(
        r'<script id="report-data" type="application/json">(.*?)</script>', page, re.DOTALL
    )
    assert data is not None
    payload = json.loads(data.group(1))
    sources = [i["source"] for c in payload["remediation"]["cases"] for i in c["investigations"]]
    assert sources == ["inferred", "inferred"]


def test_no_cases_report_is_unchanged_except_version(db, settings):
    make_scan(db, "solo", ROOT, findings=[vuln("f1")])
    report = build_report(db, "solo", settings)
    assert report.remediation is None
    assert not report.meta.ai_used
    payload = json.loads(render_json(report))
    assert "remediation" not in payload
    assert payload["meta"]["schema_version"] == "2"
    assert set(payload) == {
        "meta",
        "summary",
        "findings",
        "packages",
        "entry_points",
        "tool_runs",
        "limitations",
    }
    assert "## Remediation" not in render_markdown(report)
    page = render_html(report)
    data = re.search(r'<script id="report-data" type="application/json">(.*?)</script>', page)
    assert data is not None
    assert "remediation" not in json.loads(data.group(1))


def test_jira_url_rules(settings):
    assert jira_url(settings, "SEC-12") == f"{JIRA}/browse/SEC-12"
    assert jira_url(settings, "sec-12") is None
    assert jira_url(settings, "SEC-1/../x") is None
    assert jira_url(settings, None) is None
    assert jira_url(GuardianSettings(_env_file=None, jira_base_url=None), "SEC-1") is None


def test_ai_statements_flatten_any_shape():
    statements = ai_statements(
        {
            "relevance": "likely",
            "threat_model": {"text": "An attacker can", "evidence_refs": ["a", 1]},
            "open_questions": ["Is it exposed?"],
            "intentional_challenge_code": False,
            "modules": [{"area": "routes", "purpose": "HTTP API", "evidence_refs": []}],
            "reasons": [{"text": "  "}],
            "nested": {"no_text": True},
            "other": object(),
            "source": "inferred",
        }
    )
    assert [(s.label, s.text) for s in statements] == [
        ("Relevance", "likely"),
        ("Threat model", "An attacker can"),
        ("Open questions", "Is it exposed?"),
        ("Intentional challenge code", "no"),
        ("Modules", "routes: HTTP API"),
    ]
    assert statements[1].evidence_refs == ["a", "1"]

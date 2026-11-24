import json
from datetime import timedelta

import pytest
from jira_fake import T0, FakeJira, jira_settings, seed_case, seed_scan

from guardian.core.models import CodeDetails, Finding, FindingKind, Priority, Severity
from guardian.core.remediation_models import CaseStatus, jira_label_for
from guardian.integrations.jira import adf
from guardian.integrations.jira.client import JiraError
from guardian.integrations.jira.publish import (
    CaseContext,
    issue_summary,
    publish_case,
    publish_cases,
    select_for_publishing,
)
from guardian.storage.database import Database


@pytest.fixture
def db(tmp_path):
    with Database(tmp_path / "guardian.db") as database:
        seed_scan(database)
        yield database


def _publish(db, fake, settings, seeded, **kwargs):
    case, finding, risk, candidates, plan = seeded
    return publish_case(
        db,
        fake.client(),
        settings,
        db.remediation.get(case.id),
        findings=[finding],
        assessments=[risk],
        candidates=candidates,
        plan=plan,
        **kwargs,
    )


def test_publish_creates_once_then_updates(db, tmp_path):
    fake = FakeJira()
    settings = jira_settings(tmp_path)
    seeded = seed_case(db, status=CaseStatus.PROPOSED, inferred=True)
    case = seeded[0]

    link = _publish(db, fake, settings, seeded, dependency_paths={seeded[1].id: [["a", "b"]]})
    assert link.issue_key == "SEC-1"
    assert db.remediation.get(case.id).jira_key == "SEC-1"
    assert db.remediation.get(case.id).status is CaseStatus.AWAITING_DECISION
    created = fake.calls("POST", "/rest/api/3/issue")
    assert len(created) == 1
    fields = json.loads(created[0].content)["fields"]
    assert fields["project"] == {"key": "SEC"}
    assert fields["issuetype"] == {"name": "Bug"}
    assert fields["priority"] == {"name": "High"}
    assert fields["labels"] == ["guardian", jira_label_for(case.fingerprint), "npm", "upgrade"]
    assert fields["summary"] == (
        "[Guardian][HIGH] jsonwebtoken 0.4.0 — Verification bypass in jsonwebtoken (CVE-2015-9235)"
    )
    text = adf.adf_to_text(fields["description"])
    for expected in (
        "Score: 72.5 / 100",
        "severity\n0.35\n0.80\n[verified]",
        "exploitability\n0.20\nunknown\n[unknown]",
        "a → b",
        "GHSA-c7hr-j4mj-j2w6 affects jsonwebtoken < 4.2.2",
        "package.json:12",
        "UPGRADE",
        "pkg:npm/jsonwebtoken 0.4.0 → 4.2.2",
        "expected risk reduction 72.5 points",
        "Alternatives",
        "9.0.0",
        "major version bump",
        "git revert <commit>",
        "Guardian's assessment (AI inference)",
        "groq/gpt-oss",
        "/guardian decline reason=",
    ):
        assert expected in text, expected
    events = [e.event for e in db.audit.list(case.id)]
    assert "jira:published" in events
    assert "status:PROPOSED->AWAITING_DECISION" in events

    _publish(db, fake, settings, seeded)
    assert len(fake.calls("POST", "/rest/api/3/issue")) == 1
    assert len(fake.calls("PUT", "/rest/api/3/issue/SEC-1")) == 1
    assert len(fake.calls("POST", "/rest/api/3/search")) == 1  # link known: no 2nd search
    assert [e.event for e in db.audit.list(case.id)].count("jira:updated") == 1
    assert len(fake.issues) == 1


def test_dedup_by_label_when_link_missing(db, tmp_path):
    fake = FakeJira()
    seeded = seed_case(db)
    existing = fake.add_issue(["guardian", jira_label_for(seeded[0].fingerprint)])
    link = _publish(db, fake, jira_settings(tmp_path), seeded)
    assert link.issue_key == existing
    assert not fake.calls("POST", "/rest/api/3/issue")
    assert len(fake.calls("PUT", f"/rest/api/3/issue/{existing}")) == 1
    assert fake.jql == [f'project = "SEC" AND labels = "{jira_label_for(seeded[0].fingerprint)}"']
    assert "jira:updated" in [e.event for e in db.audit.list(seeded[0].id)]


def test_priority_field_rejected_falls_back(db, tmp_path):
    fake = FakeJira()
    fake.reject_priority = True
    seeded = seed_case(db)
    link = _publish(db, fake, jira_settings(tmp_path), seeded)
    assert "priority" not in fake.issues[link.issue_key]
    _publish(db, fake, jira_settings(tmp_path), seeded)  # update path falls back too


def test_other_jira_errors_propagate(db, tmp_path):
    fake = FakeJira()
    from httpx import Response

    fake.queued = [Response(200, json={"issues": []}), Response(400, json={"errors": {"x": "y"}})]
    with pytest.raises(JiraError):
        _publish(db, fake, jira_settings(tmp_path), seed_case(db))


def test_deterministic_plan_and_no_plan(db, tmp_path):
    fake = FakeJira()
    case, finding, _, candidates, plan = seed_case(db)
    publish_case(
        db,
        fake.client(),
        jira_settings(tmp_path),
        case,
        findings=[finding],
        assessments=[],
        candidates=candidates,
        plan=plan,
    )
    text = adf.adf_to_text(fake.issues["SEC-1"]["description"])
    assert "Selection rationale (deterministic)" in text
    assert "AI inference" not in text
    assert "No risk assessment available" in text

    publish_case(
        db,
        fake.client(),
        jira_settings(tmp_path),
        case,
        findings=[],
        assessments=[],
        candidates=[],
        plan=None,
    )
    text = adf.adf_to_text(fake.issues["SEC-1"]["description"])
    assert "No remediation plan recorded yet." in text
    assert "No evidence records." in text


def test_requires_project_key(db, tmp_path):
    with pytest.raises(JiraError, match="JIRA_PROJECT_KEY"):
        _publish(db, FakeJira(), jira_settings(tmp_path, jira_project_key=""), seed_case(db))


def test_summary_is_capped_and_cleaned(db):
    case = seed_case(db)[0]
    finding = seed_case.__globals__["vuln_finding"]()
    details = finding.details.model_copy(update={"summary": "evil\x1b[31m " + "x" * 400})
    long = finding.model_copy(update={"details": details})
    summary = issue_summary(case, [long, long])
    assert len(summary) <= 255
    assert summary.endswith("... (CVE-2015-9235) +1 more")
    assert "\x1b" not in summary
    code = Finding(
        id="c1",
        kind=FindingKind.CODE,
        title="Hard-coded secret",
        severity=Severity.HIGH,
        tool="semgrep",
        path="app.js",
        start_line=3,
        details=CodeDetails(rule_id="r", message="m"),
    )
    assert issue_summary(case, [code]) == "[Guardian][HIGH] Hard-coded secret"
    assert issue_summary(case, []) == "[Guardian][HIGH] jsonwebtoken 0.4.0"


def test_cap_top_five_at_or_above_high(db, tmp_path):
    settings = jira_settings(tmp_path)
    cases = []
    for i in range(8):
        priority = [Priority.P1, Priority.P2, Priority.P3][i % 3]
        cases.append(
            seed_case(
                db,
                package=f"pkg{i}",
                priority=priority,
                created_at=T0 + timedelta(minutes=i),
            )[0]
        )
    closed = seed_case(db, package="closed", priority=Priority.P1, status=CaseStatus.CLOSED)[0]
    selected = select_for_publishing([*cases, closed], settings)
    assert [c.priority for c in selected] == [Priority.P1] * 3 + [Priority.P2] * 2
    assert closed not in selected
    assert all(c.priority is not Priority.P3 for c in selected)

    fake = FakeJira()
    contexts = {}
    for case in cases:
        finding = seed_case.__globals__["vuln_finding"](f"pkg{cases.index(case)}")
        contexts[case.id] = CaseContext([finding], [], db.remediation.candidates(case.id), None)
    report = publish_cases(db, fake.client(), settings, cases, lambda c: contexts[c.id])
    assert len(report.links) == 5
    assert len(report.skipped) == 3
    assert len(fake.issues) == 5

    only_critical = jira_settings(tmp_path, jira_min_priority="critical", jira_max_issues=2)
    assert [c.priority for c in select_for_publishing(cases, only_critical)] == [Priority.P1] * 2


def test_publish_cases_collects_errors(db, tmp_path):
    from httpx import Response

    fake = FakeJira()
    fake.queued = [Response(403, json={"errorMessages": ["no permission"]})]
    case = seed_case(db)[0]
    report = publish_cases(
        db, fake.client(), jira_settings(tmp_path), [case], lambda c: CaseContext([], [], [], None)
    )
    assert report.links == []
    assert "HTTP 403" in report.errors[0][1]

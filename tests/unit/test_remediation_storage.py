import hashlib
import sqlite3
from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from guardian.core.exceptions import IllegalTransitionError
from guardian.core.models import Confidence, GitInfo, Priority, RepositoryProfile
from guardian.core.remediation_models import (
    CaseStatus,
    ComponentChange,
    DecisionType,
    DeclineReason,
    HumanDecision,
    ModifyPayload,
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
from guardian.storage import database as database_module
from guardian.storage.database import SCHEMA_VERSION, Database
from guardian.storage.remediation import RemediationCaseNotFoundError

T0 = datetime(2026, 1, 1, tzinfo=UTC)
ROOT = "/work/app"


@pytest.fixture
def db(tmp_path):
    with Database(tmp_path / "guardian.db") as database:
        yield database


def _scan(db, scan_id="s1"):
    repo_id = db.repositories.upsert(ROOT, "app")
    profile = RepositoryProfile(
        name="app",
        root=ROOT,
        profiled_at=T0,
        total_files=1,
        total_bytes=1,
        git=GitInfo(is_repository=True),
    )
    db.scans.create(scan_id, repo_id, T0, profile)


def _case(vuln="CVE-2021-23337"):
    fp = fingerprint_for(ROOT, "pkg:npm/lodash@4.17.20", vuln)
    return RemediationCase(
        id=case_id_for(fp),
        fingerprint=fp,
        scan_id="s1",
        repository_root=ROOT,
        finding_ids=["f1"],
        title="lodash",
        priority=Priority.P2,
        created_at=T0,
        updated_at=T0,
    )


def _candidate(case, to_version="4.17.21", position_hint=""):
    return RemediationCandidate(
        id=candidate_id_for(
            case.fingerprint, RemediationActionType.UPGRADE, "pkg:npm/lodash", to_version
        ),
        case_id=case.id,
        finding_ids=["f1"],
        action_type=RemediationActionType.UPGRADE,
        component="pkg:npm/lodash",
        from_version="4.17.20",
        to_version=to_version,
        manifest_path="package.json",
        fixes_finding_ids=["f1"],
        semver_jump=SemverJump.PATCH,
        compatibility_notes=[position_hint] if position_hint else [],
        rollback="git revert HEAD",
        expected_risk_reduction=42.5,
        version_verified=True,
        evidence=["osv:GHSA-x"],
    )


@pytest.fixture
def case(db):
    _scan(db)
    return db.remediation.create(_case())


def test_case_round_trip_and_lookup(db, case):
    assert db.remediation.get(case.id) == case
    assert db.remediation.by_fingerprint(case.fingerprint) == case
    assert db.remediation.by_fingerprint("nope") is None
    assert db.remediation.list() == [case]
    assert db.remediation.list(CaseStatus.PROPOSED) == [case]
    assert db.remediation.list(CaseStatus.APPROVED) == []
    with pytest.raises(RemediationCaseNotFoundError):
        db.remediation.get("rc_missing")
    with pytest.raises(sqlite3.IntegrityError):  # one case per fingerprint
        db.remediation.create(case)


def test_update_status_follows_state_machine_and_audits(db, case):
    moved = db.remediation.update_status(case.id, CaseStatus.AWAITING_DECISION)
    assert moved.status is CaseStatus.AWAITING_DECISION
    assert db.remediation.get(case.id) == moved
    assert db.remediation.list(CaseStatus.AWAITING_DECISION) == [moved]

    with pytest.raises(IllegalTransitionError):
        db.remediation.update_status(case.id, CaseStatus.APPLYING)
    assert db.remediation.get(case.id).status is CaseStatus.AWAITING_DECISION

    db.remediation.update_status(
        case.id, CaseStatus.APPROVED, actor="jira:acc-1", payload={"comment": "10001"}
    )
    events = db.audit.list(case.id)
    assert [e.event for e in events] == [
        "case:created",
        "status:PROPOSED->AWAITING_DECISION",
        "status:AWAITING_DECISION->APPROVED",
    ]
    assert events[-1].actor == "jira:acc-1"
    assert events[-1].payload_json == '{"comment":"10001"}'
    assert db.audit.verify() == (True, [])


def test_candidates_plans_decisions_validations_verifications(db, case):
    first, second = _candidate(case), _candidate(case, "5.0.0")
    db.remediation.save_candidates(case.id, [first, second])
    db.remediation.save_candidates(case.id, [second, first])  # re-run: upsert, reorder
    assert db.remediation.candidates(case.id) == [second, first]
    assert db.remediation.candidates("rc_other") == []

    assert db.remediation.plan(case.id) is None
    plan = RemediationPlan(
        case_id=case.id,
        chosen_candidate_id=first.id,
        alternatives=[second.id],
        rationale="patch release fixes it",
        confidence=Confidence.HIGH,
        source="verified",
        decided_by="deterministic",
    )
    newer = plan.model_copy(update={"rationale": "replanned"})
    db.remediation.save_plan(plan)
    db.remediation.save_plan(newer)
    assert db.remediation.plan(case.id) == newer

    decision = HumanDecision(
        case_id=case.id,
        decision=DecisionType.MODIFY,
        modify=ModifyPayload(version="4.17.21"),
        actor_id="acc-1",
        actor_display="Ada",
        channel="jira",
        jira_comment_id="10001",
        decided_at=T0,
    )
    decline = HumanDecision(
        case_id=case.id,
        decision=DecisionType.DECLINE,
        decline_reason=DeclineReason.ACCEPTED_RISK,
        risk_acceptance_expires=date(2026, 6, 1),
        justification="no exposure",
        actor_id="nitin",
        actor_display="nitin",
        channel="cli",
        decided_at=T0,
    )
    assert db.remediation.save_decision(decision) is True
    assert db.remediation.save_decision(decision) is False  # same Jira comment: no-op
    assert db.remediation.save_decision(decline) is True
    assert db.remediation.decisions(case.id) == [decision, decline]

    run = ValidationRun(
        case_id=case.id,
        branch=f"guardian/fix-{case.id}",
        worktree_path="/tmp/wt",
        commit_sha="abc",
        sandbox="docker",
        steps=[
            ValidationStep(name="install", status=StepStatus.PASSED, exit_code=0),
            ValidationStep(name="test", status=StepStatus.NOT_FOUND, detail="no tests"),
        ],
        tests_discovered=0,
        started_at=T0,
        finished_at=T0,
    )
    db.remediation.save_validation(run)
    assert db.remediation.validations(case.id) == [run]

    result = VerificationResult(
        case_id=case.id,
        before_scan_id="s1",
        after_scan_id="s2",
        target_findings_resolved=["f1"],
        sbom_diff=SbomDiff(
            changed=[ComponentChange(purl_base="pkg:npm/lodash", from_version="1", to_version="2")]
        ),
        risk_before=80.0,
        risk_after=10.0,
        status=VerificationStatus.PARTIALLY_VERIFIED,
        confidence=Confidence.MEDIUM,
        reasons=["no tests found"],
    )
    db.remediation.save_verification(result)
    assert db.remediation.verifications(case.id) == [result]


def test_jira_link(db, case):
    assert db.remediation.jira_link(case.id) is None
    link = db.remediation.link_jira(case.id, "SEC-1")
    assert link.issue_key == "SEC-1"
    assert link.fingerprint == case.fingerprint
    assert link.last_synced_comment_id is None
    assert db.remediation.get(case.id).jira_key == "SEC-1"
    db.remediation.link_jira(case.id, "SEC-1")  # idempotent, no second audit event
    assert [e.event for e in db.audit.list(case.id)].count("jira:linked") == 1

    db.remediation.set_last_synced_comment(case.id, "10002")
    assert db.remediation.jira_link(case.id).last_synced_comment_id == "10002"
    assert db.remediation.jira_link_by_issue("SEC-1").case_id == case.id
    assert db.remediation.jira_link_by_issue("SEC-9") is None
    with pytest.raises(RemediationCaseNotFoundError):
        db.remediation.set_last_synced_comment("rc_missing", "1")

    other = db.remediation.create(_case("CVE-2"))
    with pytest.raises(sqlite3.IntegrityError):  # one issue per case
        db.remediation.link_jira(other.id, "SEC-1")


def test_audit_chain_appends_and_verifies(db):
    first = db.audit.append(None, "config:loaded", "guardian", {"b": 2, "a": 1})
    second = db.audit.append("rc_1", "case:published", "guardian")
    assert first.prev_event_sha256 is None
    assert second.prev_event_sha256 == first.event_sha256
    assert first.payload_json == '{"a":1,"b":2}'
    assert second.payload_json == "{}"
    assert db.audit.list() == [first, second]
    assert db.audit.list("rc_1") == [second]
    assert db.audit.verify() == (True, [])


def test_audit_rows_cannot_be_updated_or_deleted(db):
    db.audit.append("rc_1", "case:created", "guardian", {"x": 1})
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        db.conn.execute("UPDATE audit_events SET actor = 'mallory'")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        db.conn.execute("DELETE FROM audit_events")
    db.conn.rollback()
    assert db.audit.verify() == (True, [])


@pytest.mark.parametrize(
    ("tamper", "problem"),
    [
        ("UPDATE audit_events SET payload_json = '{\"x\":2}' WHERE id = 1", "payload"),
        ("UPDATE audit_events SET actor = 'mallory' WHERE id = 2", "event_sha256"),
        ("DELETE FROM audit_events WHERE id = 2", "chain broken"),
        (
            (
                "UPDATE audit_events SET payload_json = '{}', "
                f"payload_sha256 = '{hashlib.sha256(b'{}').hexdigest()}' WHERE id = 1"
            ),
            "event_sha256",
        ),
    ],
)
def test_tampering_that_bypasses_triggers_is_detected(db, tamper, problem):
    for i in range(3):
        db.audit.append("rc_1", f"e{i}", "guardian", {"x": 1})
    with db.transaction() as conn:
        conn.execute("DROP TRIGGER audit_events_no_update")
        conn.execute("DROP TRIGGER audit_events_no_delete")
        conn.execute(tamper)
    ok, problems = db.audit.verify()
    assert not ok
    assert any(problem in p for p in problems)


def test_migrates_a_version_3_database(tmp_path, monkeypatch):
    path = tmp_path / "v3.db"
    monkeypatch.setattr(
        database_module,
        "MIGRATIONS",
        {k: v for k, v in database_module.MIGRATIONS.items() if k <= 3},
    )
    with Database(path) as old:
        assert old.conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] == 3
        _scan(old, "old-scan")
        assert (
            old.conn.execute(
                "SELECT name FROM sqlite_master WHERE name = 'remediation_cases'"
            ).fetchone()
            is None
        )
    monkeypatch.undo()

    with Database(path) as db:
        assert db.conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] == (
            SCHEMA_VERSION
        )
        assert db.scans.get("old-scan").repository_root == ROOT
        tables = {
            r[0] for r in db.conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        assert {
            "remediation_cases",
            "remediation_candidates",
            "remediation_plans",
            "human_decisions",
            "validation_runs",
            "verification_results",
            "jira_links",
            "audit_events",
        } <= tables
        case = _case().model_copy(update={"scan_id": "old-scan"})
        db.remediation.create(case)
        assert db.remediation.get(case.id) == case
        assert db.audit.verify() == (True, [])


def test_schema_version_includes_remediation():
    assert SCHEMA_VERSION >= 4
    assert (
        Path(database_module.__file__)
        .parent.joinpath("migrations", "004_remediation.sql")
        .is_file()
    )

from datetime import UTC, date, datetime

import httpx
import pytest
from jira_fake import (
    APPROVER_ID,
    GUARDIAN_ID,
    OUTSIDER_ID,
    FakeJira,
    jira_settings,
    seed_case,
    seed_scan,
)

from guardian.core.models import Confidence
from guardian.core.remediation_models import (
    CaseStatus,
    DecisionType,
    DeclineReason,
    SbomDiff,
    StepStatus,
    ValidationRun,
    ValidationStep,
    VerificationResult,
    VerificationStatus,
)
from guardian.integrations.decisions import decision_applies, record_decision_transition
from guardian.integrations.jira import adf
from guardian.integrations.jira.authz import is_authorized_cli, is_authorized_jira
from guardian.integrations.jira.sync import LAST_SYNC_KEY, JiraSync
from guardian.integrations.jira.writeback import (
    acknowledged_body,
    apply_transition,
    applying_body,
    comment_stage,
    failure_body,
    validation_body,
    verification_body,
)
from guardian.storage.database import Database

NOW = datetime(2026, 11, 24, 12, 0, tzinfo=UTC)


@pytest.fixture
def db(tmp_path):
    with Database(tmp_path / "guardian.db") as database:
        seed_scan(database)
        yield database


@pytest.fixture
def env(db, tmp_path):
    """A case awaiting decision, linked to issue SEC-1 on a fake Jira."""
    fake = FakeJira()
    case = seed_case(db)[0]
    key = fake.add_issue(["guardian"])
    db.remediation.link_jira(case.id, key)
    settings = jira_settings(tmp_path)
    return fake, case, key, settings


def _sync(db, fake, settings, **kwargs):
    return JiraSync(db, fake.client(), settings, **kwargs).sync_once(NOW)


def test_accept_is_recorded_acknowledged_and_transitions(db, env):
    fake, case, key, settings = env
    comment = fake.add_comment(key, APPROVER_ID, "/guardian accept")
    report = _sync(db, fake, settings)
    assert report.ok
    assert [d.decision for d in report.decisions] == [DecisionType.ACCEPT]
    decision = db.remediation.decisions(case.id)[0]
    assert decision.channel == "jira"
    assert decision.jira_comment_id == comment
    assert decision.actor_id == APPROVER_ID
    assert decision.decided_at == datetime(2026, 11, 24, 10, 0, tzinfo=UTC)
    assert db.remediation.get(case.id).status is CaseStatus.APPROVED
    assert fake.guardian_replies(key) == ["Decision acknowledged: accept by Alice."]
    assert db.remediation.jira_link(case.id).last_synced_comment_id == comment
    events = [e.event for e in db.audit.list(case.id)]
    assert "decision:recorded" in events
    assert "status:AWAITING_DECISION->APPROVED" in events
    assert db.kv.get(LAST_SYNC_KEY) == NOW.isoformat()
    assert db.audit.verify() == (True, [])


def test_resync_same_comment_is_idempotent(db, env):
    fake, case, key, settings = env
    fake.add_comment(key, APPROVER_ID, "/guardian accept")
    calls = []
    _sync(db, fake, settings, on_decision=lambda c, d: calls.append(d))
    replies = len(fake.guardian_replies(key))
    _sync(db, fake, settings, on_decision=lambda c, d: calls.append(d))
    assert len(calls) == 1
    assert len(db.remediation.decisions(case.id)) == 1
    assert len(fake.guardian_replies(key)) == replies

    # Even if the sync cursor is lost, the comment id dedupes the decision and the reply.
    db.conn.execute("UPDATE jira_links SET last_synced_comment_id = NULL")
    db.conn.commit()
    report = _sync(db, fake, settings, on_decision=lambda c, d: calls.append(d))
    assert report.duplicates == 1
    assert len(calls) == 1
    assert len(fake.guardian_replies(key)) == replies


def test_unauthorized_author_is_ignored_and_replied_to_once(db, env):
    fake, case, key, settings = env
    fake.add_comment(key, OUTSIDER_ID, "/guardian accept", display="Mallory")
    report = _sync(db, fake, settings)
    assert report.unauthorized == 1
    assert not db.remediation.decisions(case.id)
    assert db.remediation.get(case.id).status is CaseStatus.AWAITING_DECISION
    assert fake.guardian_replies(key) == [
        "Mallory: not authorized to decide on Guardian cases. The command was ignored."
    ]
    db.conn.execute("UPDATE jira_links SET last_synced_comment_id = NULL")
    db.conn.commit()
    _sync(db, fake, settings)
    assert len(fake.guardian_replies(key)) == 1
    assert [e.event for e in db.audit.list(case.id)].count("jira:unauthorized") == 1


def test_guardian_own_and_plain_comments_are_ignored(db, env, tmp_path):
    fake, case, key, _ = env
    settings = jira_settings(tmp_path, approvers=[APPROVER_ID, GUARDIAN_ID])
    fake.add_comment(key, GUARDIAN_ID, "/guardian accept", display="Guardian Bot")
    fake.add_comment(key, APPROVER_ID, "Looks good to me")
    fake.add_comment(key, OUTSIDER_ID, "random chatter")
    report = _sync(db, fake, settings)
    assert report.ignored == 3
    assert not db.remediation.decisions(case.id)
    assert len(fake.calls("POST", f"/rest/api/3/issue/{key}/comment")) == 0


def test_parse_error_replies_with_grammar_and_keeps_state(db, env):
    fake, case, key, settings = env
    fake.add_comment(key, APPROVER_ID, "/guardian accept please")
    report = _sync(db, fake, settings)
    assert report.parse_errors == 1
    assert db.remediation.get(case.id).status is CaseStatus.AWAITING_DECISION
    assert not db.remediation.decisions(case.id)
    (reply,) = fake.guardian_replies(key)
    assert "Could not parse the command: unexpected argument 'please'" in reply
    assert "/guardian revalidate" in reply
    _sync(db, fake, settings)
    assert len(fake.guardian_replies(key)) == 1


def test_decision_in_wrong_state_is_ignored(db, env):
    fake, case, key, settings = env
    fake.add_comment(key, APPROVER_ID, "/guardian revalidate")
    report = _sync(db, fake, settings)
    assert report.wrong_state == 1
    assert fake.guardian_replies(key) == ["Case is AWAITING_DECISION; decision ignored revalidate."]
    assert not db.remediation.decisions(case.id)


def test_decline_accepted_risk_closes_case(db, env):
    fake, case, key, settings = env
    fake.add_comment(
        key,
        APPROVER_ID,
        "/guardian decline reason=accepted_risk until=2027-06-30 -- intentional training vuln",
    )
    _sync(db, fake, settings)
    decision = db.remediation.decisions(case.id)[0]
    assert decision.decline_reason is DeclineReason.ACCEPTED_RISK
    assert decision.risk_acceptance_expires == date(2027, 6, 30)
    assert db.remediation.get(case.id).status is CaseStatus.CLOSED
    events = [e.event for e in db.audit.list(case.id)]
    assert "status:AWAITING_DECISION->DECLINED" in events
    assert "status:DECLINED->CLOSED" in events


def test_modify_and_multiple_comments_in_order(db, env):
    fake, case, key, settings = env
    fake.add_comment(key, APPROVER_ID, "/guardian modify version=4.2.2")
    fake.add_comment(key, APPROVER_ID, "/guardian accept")  # case no longer awaiting
    report = _sync(db, fake, settings)
    assert [d.decision for d in report.decisions] == [DecisionType.MODIFY]
    assert report.wrong_state == 1
    assert db.remediation.get(case.id).status is CaseStatus.MODIFICATION_REQUESTED


def test_revalidate_after_failed_validation(db, tmp_path):
    fake = FakeJira()
    case = seed_case(db, package="lodash", status=CaseStatus.VALIDATION_FAILED)[0]
    key = fake.add_issue(["guardian"])
    db.remediation.link_jira(case.id, key)
    seen = []
    report = _sync(db, fake, jira_settings(tmp_path), on_decision=lambda c, d: seen.append(d))
    assert report.comments_seen == 0
    fake.add_comment(key, APPROVER_ID, "/guardian revalidate")
    _sync(db, fake, jira_settings(tmp_path), on_decision=lambda c, d: seen.append(d))
    assert [d.decision for d in seen] == [DecisionType.REVALIDATE]
    # The default handler leaves the state alone for revalidate.
    assert record_decision_transition(db, case, seen[0]).status is CaseStatus.VALIDATION_FAILED


def test_handler_failure_is_reported_not_raised(db, env):
    fake, case, key, settings = env
    fake.add_comment(key, APPROVER_ID, "/guardian accept")

    def boom(c, d):
        msg = "graph unavailable"
        raise RuntimeError(msg)

    report = _sync(db, fake, settings, on_decision=boom)
    assert "decision handler failed (RuntimeError: graph unavailable)" in report.errors[0]
    assert "decision:handler_failed" in [e.event for e in db.audit.list(case.id)]
    assert db.kv.get(LAST_SYNC_KEY) is None  # not advanced: retried next time


def test_jql_uses_last_sync_in_account_time_zone(db, env, tmp_path):
    fake, _, _, settings = env
    fake.time_zone = "Asia/Kolkata"
    _sync(db, fake, settings)
    JiraSync(db, fake.client(), settings).sync_once(NOW)
    assert fake.jql[0] == 'project = "SEC" AND labels = guardian ORDER BY updated ASC'
    # 12:00 UTC - 1 min = 11:59 UTC = 17:29 IST
    assert fake.jql[1] == (
        'project = "SEC" AND labels = guardian AND updated >= "2026-11-24 17:29" '
        "ORDER BY updated ASC"
    )
    fake.time_zone = "Not/AZone"
    JiraSync(db, fake.client(), settings).sync_once(NOW)
    assert '"2026-11-24 11:59"' in fake.jql[2]


def test_unlinked_issue_and_errors(db, env, tmp_path):
    fake, _, _, settings = env
    other = fake.add_issue(["guardian"])
    report = _sync(db, fake, settings)
    assert report.unlinked_issues == [other]

    fake.queued = [httpx.Response(401)]
    report = JiraSync(db, fake.client(max_retries=0), settings).sync_once(NOW)
    assert "HTTP 401" in report.errors[0]

    report = _sync(db, fake, jira_settings(tmp_path, jira_project_key=None))
    assert report.errors == ["JIRA_PROJECT_KEY is not set"]


def test_comment_errors_on_one_issue_do_not_stop_others(db, env):
    fake, _, key, settings = env
    case2 = seed_case(db, package="lodash")[0]
    key2 = fake.add_issue(["guardian"])
    db.remediation.link_jira(case2.id, key2)
    fake.add_comment(key2, APPROVER_ID, "/guardian accept")
    fake.comments.pop(key)  # SEC-1 comments now fail with HTTP 500
    report = _sync(db, fake, settings)
    assert any(key in e for e in report.errors)
    assert db.remediation.get(case2.id).status is CaseStatus.APPROVED


def test_watch_loops_and_stops_on_ctrl_c(db, env):
    fake, _, _, settings = env
    sleeps = []
    syncer = JiraSync(db, fake.client(), settings, sleep=sleeps.append)
    reports = []
    assert syncer.watch(on_report=reports.append, max_iterations=3, clock=lambda: NOW) == 3
    assert len(reports) == 3
    assert sleeps == [30.0, 30.0]

    def interrupt(_):
        raise KeyboardInterrupt

    syncer = JiraSync(db, fake.client(), settings, sleep=interrupt)
    assert syncer.watch(clock=lambda: NOW) == 1


def test_bad_comment_records_are_skipped(db, env):
    fake, _, key, settings = env
    fake.comments[key] = [
        {"id": "abc", "author": {"accountId": APPROVER_ID}, "body": "/guardian accept"},
        {"id": "20000", "author": "weird", "body": "/guardian accept", "created": "yesterday"},
    ]
    report = _sync(db, fake, settings)
    assert report.comments_seen == 1
    assert report.unauthorized == 1  # no author id -> never authorized


# --- authz and decisions ---------------------------------------------------------------------


def test_authz(tmp_path):
    settings = jira_settings(tmp_path, approvers=[APPROVER_ID, GUARDIAN_ID])
    assert is_authorized_jira(APPROVER_ID, settings, guardian_account_id=GUARDIAN_ID)
    assert not is_authorized_jira(GUARDIAN_ID, settings, guardian_account_id=GUARDIAN_ID)
    assert not is_authorized_jira(OUTSIDER_ID, settings)
    assert not is_authorized_jira(None, settings)
    assert is_authorized_cli("alice", settings)
    assert not is_authorized_cli("bob", settings)
    assert not is_authorized_cli("", settings)
    empty = jira_settings(tmp_path, approvers=[], cli_approvers=[])
    assert not is_authorized_jira(APPROVER_ID, empty)
    assert not is_authorized_cli("alice", empty)


def test_decision_applies(db):
    case = seed_case(db)[0]
    assert decision_applies(case, DecisionType.ACCEPT)
    assert not decision_applies(case, DecisionType.REVALIDATE)


# --- write-back ------------------------------------------------------------------------------


def test_comment_stage_is_idempotent_and_transitions(db, env, tmp_path):
    fake, case, key, _ = env
    settings = jira_settings(tmp_path, jira_transitions={"verified": "Done"})
    link = db.remediation.jira_link(case.id)
    jira = fake.client()
    body = applying_body("guardian/fix-rc_1", "cand_0123456789ab")
    assert comment_stage(db, jira, link, "applying", body)
    assert not comment_stage(db, jira, link, "applying", body)
    assert comment_stage(db, jira, link, "applying", body, key="attempt-2")
    assert len(fake.guardian_replies(key)) == 2
    assert "guardian/fix-rc_1" in fake.guardian_replies(key)[0]

    result = VerificationResult(
        case_id=case.id,
        before_scan_id="scan-1",
        after_scan_id="scan-2",
        target_findings_resolved=["f1"],
        sbom_diff=SbomDiff(added=["pkg:npm/a@1"]),
        risk_before=72.5,
        risk_after=10.0,
        status=VerificationStatus.VERIFIED,
        confidence=Confidence.HIGH,
        reasons=["targeted finding resolved"],
    )
    assert comment_stage(
        db,
        jira,
        link,
        "verification",
        verification_body(result),
        settings=settings,
        transition="verified",
    )
    assert fake.transitioned == [(key, "31")]
    text = fake.guardian_replies(key)[-1]
    assert "[VERIFIED]" in text
    assert "72.5\n10.0" in text
    assert "+1 / -0 / ~0" in text
    assert "jira:transitioned" in [e.event for e in db.audit.list(case.id)]


def test_transition_variants(db, env, tmp_path):
    fake, case, _, _ = env
    link = db.remediation.jira_link(case.id)
    jira = fake.client()
    assert not apply_transition(db, jira, jira_settings(tmp_path), link, "verified")
    settings = jira_settings(tmp_path, jira_transitions={"declined": "Won't Do"})
    assert not apply_transition(db, jira, settings, link, "declined")
    fake.queued = [httpx.Response(403)]
    assert not apply_transition(db, fake.client(max_retries=0), settings, link, "declined")
    events = [e.event for e in db.audit.list(case.id)]
    assert "jira:transition_unavailable" in events
    assert "jira:transition_failed" in events


def test_stage_bodies_render(db):
    case = seed_case(db)[0]
    run = ValidationRun(
        case_id=case.id,
        branch="guardian/fix-x",
        worktree_path="/tmp/w",
        sandbox="docker",
        steps=[
            ValidationStep(name="build", status=StepStatus.PASSED, exit_code=0),
            ValidationStep(name="test", status=StepStatus.FAILED, exit_code=1, detail="2 failed"),
        ],
        tests_discovered=10,
        tests_passed=8,
        tests_failed=2,
        started_at=datetime(2026, 11, 24, tzinfo=UTC),
    )
    text = adf.adf_to_text(validation_body(run))
    assert "8 passed, 2 failed of 10" in text
    assert "[failed]" in text
    empty = run.model_copy(update={"steps": [], "tests_discovered": None})
    assert "no tests discovered" in adf.adf_to_text(validation_body(empty))
    failure = adf.adf_to_text(failure_body("tests failed", ["2 tests failed"]))
    assert "back in review" in failure
    from guardian.integrations.jira.commands import parse_command, to_decision

    decision = to_decision(
        parse_command("/guardian accept"), case.id, "a", "Alice", "cli", None, NOW
    )
    assert adf.adf_to_text(acknowledged_body(decision, "accept")) == (
        "Decision acknowledged: accept by Alice via cli."
    )

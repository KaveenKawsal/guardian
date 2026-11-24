from datetime import UTC, datetime, timedelta

import pytest

from guardian.core.models import Confidence, Priority
from guardian.core.remediation_models import (
    AuditEvent,
    CaseStatus,
    DecisionType,
    DeclineReason,
    HumanDecision,
    RemediationCase,
    StepStatus,
    ValidationRun,
    ValidationStep,
    VerificationResult,
    VerificationStatus,
)
from guardian.ui.journey import build_journey

T0 = datetime(2026, 1, 1, tzinfo=UTC)


def case(status):
    return RemediationCase(
        id="rc_000000000001",
        fingerprint="f" * 40,
        scan_id="s1",
        repository_root="/r",
        title="t",
        priority=Priority.P2,
        status=status,
        created_at=T0,
        updated_at=T0,
    )


def event(name, minutes):
    return AuditEvent(
        case_id="rc_000000000001",
        event=name,
        actor="guardian",
        at=T0 + timedelta(minutes=minutes),
        payload_json="{}",
        payload_sha256="0",
        event_sha256="0",
    )


def run(minutes, *, failed=False, finished=True):
    return ValidationRun(
        case_id="rc_000000000001",
        branch="guardian/fix-rc_000000000001",
        worktree_path="/w",
        sandbox="docker",
        steps=[
            ValidationStep(name="build", status=StepStatus.PASSED),
            ValidationStep(name="test", status=StepStatus.FAILED if failed else StepStatus.PASSED),
        ],
        started_at=T0 + timedelta(minutes=minutes),
        finished_at=T0 + timedelta(minutes=minutes + 1) if finished else None,
    )


def verification(status):
    return VerificationResult(
        case_id="rc_000000000001",
        before_scan_id="s1",
        status=status,
        confidence=Confidence.LOW,
    )


def decision(kind=DecisionType.ACCEPT):
    extra = {}
    if kind is DecisionType.DECLINE:
        extra = {"decline_reason": DeclineReason.WONT_FIX}
    return HumanDecision(
        case_id="rc_000000000001",
        decision=kind,
        actor_id="alice",
        actor_display="alice (local UI)",
        channel="cli",
        decided_at=T0,
        **extra,
    )


APPLY_EVENTS = [
    event("status:PROPOSED->AWAITING_DECISION", 1),
    event("status:AWAITING_DECISION->APPROVED", 2),
    event("status:APPROVED->APPLYING", 3),
]


def states(journey):
    return {s["key"]: s["state"] for s in journey.to_json()["stations"]}


def test_proposed():
    j = build_journey(case(CaseStatus.PROPOSED), [], [], [], [])
    assert states(j)["fix"] == "current"
    assert states(j)["risk"] == "done"
    assert j.live is False


@pytest.mark.parametrize(
    "status", [CaseStatus.APPROVED, CaseStatus.MODIFICATION_REQUESTED, CaseStatus.APPLYING]
)
def test_applying_is_live(status):
    j = build_journey(case(status), [decision()], [], [], APPLY_EVENTS)
    assert states(j)["apply"] == "current"
    assert states(j)["decision"] == "done"
    assert j.live is True
    assert j.stations[2].note == "accept by alice (local UI)"


def test_validating_build_then_rescan():
    events = [*APPLY_EVENTS, event("status:APPLYING->VALIDATING", 4)]
    j = build_journey(
        case(CaseStatus.VALIDATING), [decision()], [run(3, finished=False)], [], events
    )
    assert states(j)["build"] == "current"
    j = build_journey(case(CaseStatus.VALIDATING), [decision()], [run(3)], [], events)
    assert states(j)["rescan"] == "current"
    assert states(j)["build"] == "done"
    assert j.stations[3].note == "guardian/fix-rc_000000000001"


def test_failed_in_build_loops_back():
    events = [*APPLY_EVENTS, event("status:VALIDATING->VALIDATION_FAILED", 6)]
    j = build_journey(
        case(CaseStatus.VALIDATION_FAILED), [decision()], [run(3, failed=True)], [], events
    )
    assert states(j)["build"] == "failed"
    assert j.loop_back is True
    assert j.failed_attempts == 1


def test_failed_while_applying():
    events = [*APPLY_EVENTS, event("status:APPLYING->VALIDATION_FAILED", 4)]
    j = build_journey(case(CaseStatus.VALIDATION_FAILED), [decision()], [], [], events)
    assert states(j)["apply"] == "failed"


def test_failed_at_rescan_and_fallback():
    events = [*APPLY_EVENTS, event("status:VALIDATING->VALIDATION_FAILED", 6)]
    j = build_journey(
        case(CaseStatus.VALIDATION_FAILED),
        [decision()],
        [run(3)],
        [verification(VerificationStatus.FAILED)],
        events,
    )
    assert states(j)["rescan"] == "failed"
    assert j.stations[-1].note == "failed"
    j = build_journey(case(CaseStatus.VALIDATION_FAILED), [decision()], [], [], [])
    assert states(j)["build"] == "failed"


def test_back_in_review_after_failure():
    j = build_journey(
        case(CaseStatus.AWAITING_DECISION),
        [decision()],
        [run(3, failed=True)],
        [verification(VerificationStatus.FAILED)],
        APPLY_EVENTS,
        decision_pending=True,
    )
    assert states(j)["decision"] == "current"
    assert j.loop_back is True
    assert j.live is True
    assert j.notes


def test_closed_after_verified_and_after_decline():
    j = build_journey(case(CaseStatus.CLOSED), [decision()], [run(3)], [], [])
    assert set(states(j).values()) == {"done"}
    j = build_journey(case(CaseStatus.DECLINED), [decision(DecisionType.DECLINE)], [], [], [])
    assert j.branch == {"reason": "WONT_FIX", "until": None, "justification": None}
    assert states(j)["apply"] == "skipped"
    j = build_journey(case(CaseStatus.DECLINED), [], [], [], [])
    assert j.branch == {"reason": None, "until": None, "justification": None}

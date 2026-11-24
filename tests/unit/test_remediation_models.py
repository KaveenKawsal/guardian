from datetime import UTC, date, datetime

import pytest
from pydantic import ValidationError

from guardian.core import models
from guardian.core.exceptions import IllegalTransitionError
from guardian.core.models import Confidence, Priority
from guardian.core.remediation_models import (
    ALLOWED_TRANSITIONS,
    CaseStatus,
    DecisionType,
    DeclineReason,
    HumanDecision,
    ModifyPayload,
    RemediationActionType,
    RemediationCandidate,
    RemediationCase,
    RemediationPlan,
    candidate_id_for,
    canonical_json,
    case_id_for,
    fingerprint_for,
    jira_label_for,
)

T0 = datetime(2026, 1, 1, tzinfo=UTC)
T1 = datetime(2026, 1, 2, tzinfo=UTC)


def _case(status=CaseStatus.PROPOSED):
    fp = fingerprint_for("/work/app", "pkg:npm/lodash@4.17.20", "CVE-2021-23337")
    return RemediationCase(
        id=case_id_for(fp),
        fingerprint=fp,
        scan_id="s1",
        repository_root="/work/app",
        finding_ids=["f1"],
        title="lodash 4.17.20 - command injection",
        priority=Priority.P2,
        status=status,
        created_at=T0,
        updated_at=T0,
    )


def _decision(**kw):
    base = {
        "case_id": "rc_1",
        "decision": DecisionType.ACCEPT,
        "actor_id": "acc-1",
        "actor_display": "Ada",
        "channel": "jira",
        "decided_at": T0,
    }
    return HumanDecision(**(base | kw))


ALL_EDGES = [(src, dst) for src, dsts in ALLOWED_TRANSITIONS.items() for dst in dsts]


@pytest.mark.parametrize(("src", "dst"), ALL_EDGES)
def test_every_allowed_transition_works(src, dst):
    case = _case(src)
    moved = case.transition(dst, at=T1)
    assert moved.status is dst
    assert moved.updated_at == T1
    assert case.status is src  # the original is unchanged (frozen)


def test_state_machine_has_exactly_the_contract_edges():
    s = CaseStatus
    expected = {
        (s.PROPOSED, s.AWAITING_DECISION),
        (s.AWAITING_DECISION, s.DECLINED),
        (s.AWAITING_DECISION, s.APPROVED),
        (s.AWAITING_DECISION, s.MODIFICATION_REQUESTED),
        (s.APPROVED, s.APPLYING),
        (s.MODIFICATION_REQUESTED, s.APPLYING),
        (s.APPLYING, s.VALIDATING),
        (s.APPLYING, s.VALIDATION_FAILED),
        (s.VALIDATING, s.VERIFIED),
        (s.VALIDATING, s.VALIDATION_FAILED),
        (s.VALIDATION_FAILED, s.AWAITING_DECISION),
        (s.VERIFIED, s.CLOSED),
        (s.DECLINED, s.CLOSED),
    }
    assert set(ALL_EDGES) == expected
    assert set(ALLOWED_TRANSITIONS) == set(CaseStatus)


@pytest.mark.parametrize(
    ("src", "dst"),
    [
        (CaseStatus.PROPOSED, CaseStatus.APPROVED),  # no decision skipped
        (CaseStatus.PROPOSED, CaseStatus.APPLYING),
        (CaseStatus.AWAITING_DECISION, CaseStatus.APPLYING),  # apply needs approval
        (CaseStatus.DECLINED, CaseStatus.APPLYING),
        (CaseStatus.APPROVED, CaseStatus.VERIFIED),
        (CaseStatus.VALIDATING, CaseStatus.CLOSED),
        (CaseStatus.VALIDATION_FAILED, CaseStatus.APPLYING),
        (CaseStatus.CLOSED, CaseStatus.PROPOSED),
        (CaseStatus.VERIFIED, CaseStatus.VERIFIED),
    ],
)
def test_illegal_transitions_raise(src, dst):
    with pytest.raises(IllegalTransitionError, match=f"{src.value} -> {dst.value}"):
        _case(src).transition(dst)


def test_cases_are_frozen():
    with pytest.raises(ValidationError):
        _case().status = CaseStatus.APPROVED  # type: ignore[misc]


def test_ids_are_deterministic():
    fp = fingerprint_for("/r", "pkg:npm/a@1", "CVE-1")
    assert fp == fingerprint_for("/r", "pkg:npm/a@1", "CVE-1")
    assert len(fp) == 40
    assert fp != fingerprint_for("/r", "pkg:npm/a@1", "CVE-2")
    # A separator stops fields from running into each other.
    assert fingerprint_for("/ra", "b", "c") != fingerprint_for("/r", "ab", "c")
    assert case_id_for(fp) == f"rc_{fp[:12]}"
    assert jira_label_for(fp) == f"guardian-fp-{fp[:16]}"
    cand = candidate_id_for(fp, RemediationActionType.UPGRADE, "pkg:npm/a@1", "1.0.1")
    assert cand.startswith("cand_")
    assert len(cand) == len("cand_") + 12
    assert cand == candidate_id_for(fp, RemediationActionType.UPGRADE, "pkg:npm/a@1", "1.0.1")
    assert cand != candidate_id_for(fp, RemediationActionType.UPGRADE, "pkg:npm/a@1", "2.0.0")
    assert cand != candidate_id_for(fp, RemediationActionType.PIN, "pkg:npm/a@1", "1.0.1")
    assert candidate_id_for(fp, RemediationActionType.BLOCK, "pkg:npm/a@1", None).startswith(
        "cand_"
    )


def test_canonical_json():
    assert canonical_json({"b": 1, "a": [T0]}) == '{"a":["2026-01-01 00:00:00+00:00"],"b":1}'
    assert canonical_json(ModifyPayload(version="1.2.3")).startswith('{"action":null')


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("P1", Priority.P1),
        ("p2", Priority.P2),
        ("HIGH", Priority.P2),
        ("high", Priority.P2),
        (" Medium ", Priority.P3),
        ("critical", Priority.P1),
        ("LOW", Priority.P4),
    ],
)
def test_priority_parse(text, expected):
    assert Priority.parse(text) is expected


def test_priority_parse_rejects_unknown_and_labels():
    with pytest.raises(ValueError, match="Unknown priority"):
        Priority.parse("urgent")
    assert [p.label for p in Priority] == ["critical", "high", "medium", "low"]


@pytest.mark.parametrize(
    "kw",
    [
        {"candidate_id": "cand_x"},
        {"version": "1.2.3"},
        {"action": RemediationActionType.PIN},
        {"action": RemediationActionType.REPLACE, "target": "pkg:npm/b"},
        {"branch": "fix/manual"},
        {"commit": "abc123"},
    ],
)
def test_modify_payload_accepts_one_kind(kw):
    payload = ModifyPayload(**kw)
    assert payload.kind in kw


@pytest.mark.parametrize(
    "kw",
    [
        {},
        {"version": "1.2.3", "branch": "x"},
        {"candidate_id": "c", "action": RemediationActionType.PIN},
        {"branch": "x", "commit": "y"},
        {"target": "pkg:npm/b"},  # target without action
        {"version": "1", "target": "pkg:npm/b"},
    ],
)
def test_modify_payload_rejects_zero_or_several_kinds(kw):
    with pytest.raises(ValidationError):
        ModifyPayload(**kw)


def test_decision_validators():
    assert _decision(candidate_id="cand_1").candidate_id == "cand_1"
    assert _decision(decision=DecisionType.REVALIDATE).decision is DecisionType.REVALIDATE
    modify = _decision(decision=DecisionType.MODIFY, modify=ModifyPayload(version="2.0.0"))
    assert modify.modify is not None
    declined = _decision(decision=DecisionType.DECLINE, decline_reason=DeclineReason.WONT_FIX)
    assert declined.decline_reason is DeclineReason.WONT_FIX
    accepted_risk = _decision(
        decision=DecisionType.DECLINE,
        decline_reason=DeclineReason.ACCEPTED_RISK,
        risk_acceptance_expires=date(2026, 6, 1),
        justification="internal tool, no network exposure",
    )
    assert accepted_risk.risk_acceptance_expires == date(2026, 6, 1)


@pytest.mark.parametrize(
    ("kw", "match"),
    [
        ({"decision": DecisionType.MODIFY}, "needs a modify payload"),
        ({"modify": ModifyPayload(version="1")}, "Only a MODIFY"),
        ({"decision": DecisionType.DECLINE}, "needs a decline_reason"),
        ({"decline_reason": DeclineReason.DUPLICATE}, "Only a DECLINE"),
        (
            {"decision": DecisionType.DECLINE, "decline_reason": DeclineReason.ACCEPTED_RISK},
            "accepted_risk requires",
        ),
        (
            {
                "decision": DecisionType.DECLINE,
                "decline_reason": DeclineReason.ACCEPTED_RISK,
                "risk_acceptance_expires": date(2026, 6, 1),
                "justification": "  ",
            },
            "accepted_risk requires",
        ),
        (
            {
                "decision": DecisionType.DECLINE,
                "decline_reason": DeclineReason.ACCEPTED_RISK,
                "justification": "fine",
            },
            "accepted_risk requires",
        ),
        (
            {
                "decision": DecisionType.DECLINE,
                "decline_reason": DeclineReason.WONT_FIX,
                "candidate_id": "c",
            },
            "candidate_id is only valid on ACCEPT",
        ),
        ({"channel": "slack"}, "channel"),
    ],
)
def test_decision_rejects_inconsistent_input(kw, match):
    with pytest.raises(ValidationError, match=match):
        _decision(**kw)


def test_plan_source_must_match_decider():
    plan = RemediationPlan(
        case_id="rc_1",
        chosen_candidate_id="cand_1",
        rationale="lowest jump",
        confidence=Confidence.HIGH,
        source="verified",
        decided_by="deterministic",
    )
    assert plan.source == "verified"
    with pytest.raises(ValidationError, match="source='inferred'"):
        RemediationPlan(
            case_id="rc_1",
            chosen_candidate_id="cand_1",
            rationale="llm says so",
            confidence=Confidence.LOW,
            source="verified",
            decided_by="llm",
        )


def test_candidate_source_is_always_verified():
    with pytest.raises(ValidationError):
        RemediationCandidate(
            id="cand_1",
            case_id="rc_1",
            action_type=RemediationActionType.UPGRADE,
            component="pkg:npm/a@1",
            rollback="git revert HEAD",
            source="inferred",  # type: ignore[arg-type]
        )


def test_models_module_re_exports_remediation_names():
    assert models.RemediationCase is RemediationCase
    assert models.CaseStatus is CaseStatus
    with pytest.raises(AttributeError):
        _ = models.NotAThing  # type: ignore[attr-defined]

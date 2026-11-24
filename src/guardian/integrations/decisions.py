"""Channel-neutral handling of a recorded human decision (Jira comment or ``guardian decide``).

``decision_applies`` says whether a decision may act on a case in its current state.

The live reaction to a decision is the remediation graph
(``guardian.remediation.runtime.submit_decision``): its ``apply`` / ``record_acceptance`` nodes
move the case out of AWAITING_DECISION. ``record_decision_transition`` is the pre-graph reaction,
kept only for tests and back-compat (it moves the case along the state machine directly and
must never be combined with the graph for the same decision).

REVALIDATE: with the graph, a failed attempt returns the case to AWAITING_DECISION, so
REVALIDATE applies there once an earlier ACCEPT/MODIFY was acted on (``can_revalidate``;
see ``revalidate_ready``). VALIDATION_FAILED and VERIFIED stay accepted for back-compat.
"""

from guardian.core.remediation_models import (
    CaseStatus,
    DecisionType,
    HumanDecision,
    RemediationCase,
)
from guardian.storage.database import Database

_STATES_FOR: dict[DecisionType, frozenset[CaseStatus]] = {
    DecisionType.ACCEPT: frozenset({CaseStatus.AWAITING_DECISION}),
    DecisionType.MODIFY: frozenset({CaseStatus.AWAITING_DECISION}),
    DecisionType.DECLINE: frozenset({CaseStatus.AWAITING_DECISION}),
    DecisionType.REVALIDATE: frozenset({CaseStatus.VALIDATION_FAILED, CaseStatus.VERIFIED}),
}


def decision_applies(
    case: RemediationCase, decision: DecisionType, *, can_revalidate: bool = False
) -> bool:
    if (
        decision is DecisionType.REVALIDATE
        and can_revalidate
        and case.status is CaseStatus.AWAITING_DECISION
    ):
        return True
    return case.status in _STATES_FOR[decision]


def revalidate_ready(db: Database, case_id: str) -> bool:
    """True when the case went through a failed attempt after an ACCEPT/MODIFY decision, so a
    REVALIDATE has a change to re-run."""
    approved = any(
        d.decision in {DecisionType.ACCEPT, DecisionType.MODIFY}
        for d in db.remediation.decisions(case_id)
    )
    if not approved:
        return False
    suffix = f"->{CaseStatus.VALIDATION_FAILED.value}"
    return any(
        e.event.startswith("status:") and e.event.endswith(suffix) for e in db.audit.list(case_id)
    )


def decision_actor(decision: HumanDecision) -> str:
    return f"{decision.channel}:{decision.actor_id}"


def record_decision_transition(
    db: Database, case: RemediationCase, decision: HumanDecision
) -> RemediationCase:
    """Default reaction to a decision: ACCEPT -> APPROVED, MODIFY -> MODIFICATION_REQUESTED,
    DECLINE -> DECLINED -> CLOSED (accepted risk keeps its expiry on the decision itself).
    REVALIDATE changes no state here; re-running validation is the orchestrator's job."""
    actor = decision_actor(decision)
    payload = {"decision": decision.decision.value, "jira_comment_id": decision.jira_comment_id}
    current = db.remediation.get(case.id)
    if decision.decision is DecisionType.ACCEPT:
        return db.remediation.update_status(
            case.id, CaseStatus.APPROVED, actor=actor, payload=payload
        )
    if decision.decision is DecisionType.MODIFY:
        return db.remediation.update_status(
            case.id, CaseStatus.MODIFICATION_REQUESTED, actor=actor, payload=payload
        )
    if decision.decision is DecisionType.DECLINE:
        reason = decision.decline_reason.value if decision.decline_reason else None
        expires = decision.risk_acceptance_expires
        payload |= {
            "decline_reason": reason,
            "risk_acceptance_expires": expires.isoformat() if expires else None,
        }
        db.remediation.update_status(case.id, CaseStatus.DECLINED, actor=actor, payload=payload)
        return db.remediation.update_status(
            case.id, CaseStatus.CLOSED, actor=actor, payload=payload
        )
    return current

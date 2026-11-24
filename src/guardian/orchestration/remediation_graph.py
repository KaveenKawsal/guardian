"""Remediation graph B: one durable LangGraph thread per case (``thread_id = case_id``).

```
plan -> publish_jira -> await_decision
await_decision --ACCEPT/MODIFY/REVALIDATE--> apply -> validate -> rescan_verify
await_decision --DECLINE--> record_acceptance -> report_back -> END
rescan_verify  --VERIFIED--> report_back -> END
rescan_verify / apply / validate --failed--> publish_failure -> await_decision
(the re-review loop is a conditional edge in the graph, not a loop inside a node)
```

Rules this module keeps (ADR 11):

* ``await_decision`` has no side effects. It only reads the case and calls ``interrupt``. LangGraph
  replays an interrupted node from its start on resume, so anything it wrote would be written
  twice. An invalid resume payload does not raise there: LangGraph would store the bad value and
  replay it on every later resume, so the node interrupts again with an ``error`` instead.
  ``resume_case`` validates before invoking and raises ``ValueError``, so a bad decision fails
  loudly without touching the thread.
* Decisions arrive already parsed by the deterministic grammar (Jira sync or ``guardian decide``).
  The graph re-validates them with ``HumanDecision.model_validate`` and never asks an LLM.
* Every status change goes through ``RemediationStore.update_status`` (which audits it) and is
  guarded: a replayed node checks the current status and skips the edges it already took.
* Side-effect nodes call idempotent services and append one ``graph:<node>`` audit event per
  attempt (also guarded, so replays do not duplicate it).
"""

import json
from dataclasses import dataclass
from typing import Any, Literal, TypeAlias

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import Command, StateSnapshot, interrupt

from guardian.core.exceptions import GuardianError, IllegalTransitionError
from guardian.core.remediation_models import (
    CaseStatus,
    DecisionType,
    HumanDecision,
    VerificationStatus,
)
from guardian.orchestration.services import RemediationServices
from guardian.orchestration.state import RemediationState
from guardian.storage.database import Database
from guardian.storage.remediation import SYSTEM_ACTOR

RemediationGraph: TypeAlias = CompiledStateGraph[Any, Any, Any, Any]

AWAIT_NODE = "await_decision"
_DURABILITY: Literal["sync"] = "sync"
"""Persist each step before the next starts, so a crash replays at most the failing node."""


class CaseNotAwaitingDecisionError(GuardianError):
    """The case's graph thread is not paused at ``await_decision``."""


class CaseThreadNotResumableError(GuardianError):
    """The case's graph thread has nothing pending to retry."""


@dataclass(frozen=True)
class InterruptInfo:
    case_id: str
    interrupt_id: str
    payload: dict[str, Any]
    """The case summary ``await_decision`` handed to the human."""


@dataclass(frozen=True)
class RunResult:
    case_id: str
    values: dict[str, Any]
    interrupt: InterruptInfo | None
    finished: bool
    """True when the thread reached END (the case is CLOSED)."""


def _actor(decision: HumanDecision) -> str:
    return f"{decision.channel}:{decision.actor_id}"


class _Nodes:
    def __init__(self, db: Database, services: RemediationServices) -> None:
        self.db = db
        self.services = services

    # --- guards --------------------------------------------------------------------------

    def _status(self, case_id: str) -> CaseStatus:
        return self.db.remediation.get(case_id).status

    def _walk(
        self,
        case_id: str,
        chain: list[tuple[CaseStatus, str]],
        payload: dict[str, Any],
    ) -> None:
        """Take the remaining edges of ``chain`` (``(status, actor)`` pairs, first = start).

        A replayed node finds the case part-way along the chain and continues from there.
        A case outside the chain is a real inconsistency, so it raises.
        """
        statuses = [status for status, _ in chain]
        current = self._status(case_id)
        if current not in statuses:
            path = " -> ".join(s.value for s in statuses)
            msg = f"Case {case_id} is {current.value}; expected a status on {path}"
            raise IllegalTransitionError(msg)
        for to, actor in chain[statuses.index(current) + 1 :]:
            self.db.remediation.update_status(case_id, to, actor=actor, payload=payload)

    def _audited(self, case_id: str, event: str, attempt: int) -> dict[str, Any] | None:
        """Payload of the ``event`` already recorded for ``attempt``, if any."""
        for recorded in self.db.audit.list(case_id):
            if recorded.event == event:
                payload = json.loads(recorded.payload_json)
                if payload.get("attempt") == attempt:
                    return payload
        return None

    def _audit_once(
        self, case_id: str, node: str, attempt: int, payload: dict[str, Any] | None = None
    ) -> None:
        event = f"graph:{node}"
        if self._audited(case_id, event, attempt) is None:
            self.db.audit.append(
                case_id, event, SYSTEM_ACTOR, {"attempt": attempt, **(payload or {})}
            )

    def _notify_once(self, case_id: str, stage: str, attempt: int, payload: dict[str, Any]) -> None:
        event = f"graph:notify:{stage}"
        if self._audited(case_id, event, attempt) is not None:
            return
        body = {"attempt": attempt, **payload}
        self.services.notify(case_id, stage, body)
        self.db.audit.append(case_id, event, SYSTEM_ACTOR, body)

    # --- nodes ---------------------------------------------------------------------------

    def plan(self, state: RemediationState) -> dict[str, Any]:
        case_id = state["case_id"]
        attempt = state.get("attempt", 1)
        self.services.plan(case_id)
        if self._status(case_id) is CaseStatus.PROPOSED:
            self._walk(
                case_id,
                [(CaseStatus.PROPOSED, SYSTEM_ACTOR), (CaseStatus.AWAITING_DECISION, SYSTEM_ACTOR)],
                {"attempt": attempt, "node": "plan"},
            )
        self._audit_once(case_id, "plan", attempt)
        return {"attempt": attempt, "last_event": "planned"}

    def publish_jira(self, state: RemediationState) -> dict[str, Any]:
        case_id = state["case_id"]
        attempt = state.get("attempt", 1)
        jira_key = self.services.publish(case_id)
        self._audit_once(case_id, "publish_jira", attempt, {"jira_key": jira_key})
        return {"jira_key": jira_key, "last_event": "published"}

    def await_decision(self, state: RemediationState) -> dict[str, Any]:
        """Pause for a human. No side effects: this whole function replays on resume."""
        case_id = state["case_id"]
        case = self.db.remediation.get(case_id)
        verification = state.get("verification") or {}
        summary: dict[str, Any] = {
            "case_id": case_id,
            "title": case.title,
            "priority": case.priority.value,
            "status": case.status.value,
            "jira_key": state.get("jira_key"),
            "attempt": state.get("attempt", 1),
            "last_event": state.get("last_event"),
            "last_verification": verification.get("status"),
            "last_error": state.get("error"),
        }
        payload = interrupt(summary)
        while True:
            try:
                decision, effective = self._parse_decision(state, payload)
                break
            except ValueError as exc:
                payload = interrupt({**summary, "error": str(exc)})
        return {
            "received_decision": decision.model_dump(mode="json"),
            "decision": effective.model_dump(mode="json"),
            "last_event": "decision_received",
        }

    @staticmethod
    def _parse_decision(
        state: RemediationState, payload: object
    ) -> tuple[HumanDecision, HumanDecision]:
        """(received, effective). Raises ``ValueError`` (pydantic's included) when invalid."""
        decision = HumanDecision.model_validate(payload)
        if decision.case_id != state["case_id"]:
            msg = f"Decision is for {decision.case_id}, not {state['case_id']}"
            raise ValueError(msg)
        if decision.decision is not DecisionType.REVALIDATE:
            return decision, decision
        previous = state.get("decision")
        if previous is None:
            msg = "REVALIDATE needs an earlier ACCEPT or MODIFY decision on this case"
            raise ValueError(msg)
        effective = HumanDecision.model_validate(previous)
        if effective.decision not in {DecisionType.ACCEPT, DecisionType.MODIFY}:
            msg = "REVALIDATE needs an earlier ACCEPT or MODIFY decision on this case"
            raise ValueError(msg)
        return decision, effective

    def apply(self, state: RemediationState) -> dict[str, Any]:
        case_id = state["case_id"]
        attempt = state.get("attempt", 1)
        received = HumanDecision.model_validate(state.get("received_decision"))
        effective = HumanDecision.model_validate(state.get("decision"))
        if self._status(case_id) is CaseStatus.VALIDATION_FAILED:
            # Replay after the failure below was recorded but before the checkpoint was.
            recorded = self._audited(case_id, "graph:apply", attempt) or {}
            return self._apply_failed(str(recorded.get("error", "apply failed")))
        approved = (
            CaseStatus.MODIFICATION_REQUESTED
            if received.decision is DecisionType.MODIFY
            else CaseStatus.APPROVED
        )
        self._walk(
            case_id,
            [
                (CaseStatus.AWAITING_DECISION, SYSTEM_ACTOR),
                (approved, _actor(received)),
                (CaseStatus.APPLYING, SYSTEM_ACTOR),
            ],
            {
                "attempt": attempt,
                "node": "apply",
                "decision": received.decision.value,
                "jira_comment_id": received.jira_comment_id,
            },
        )
        try:
            applied = self.services.apply(case_id, effective)
        except GuardianError as exc:
            error = str(exc)
            self._walk(
                case_id,
                [(CaseStatus.APPLYING, SYSTEM_ACTOR), (CaseStatus.VALIDATION_FAILED, SYSTEM_ACTOR)],
                {"attempt": attempt, "node": "apply", "error": error},
            )
            self._audit_once(case_id, "apply", attempt, {"error": error})
            return self._apply_failed(error)
        self._audit_once(case_id, "apply", attempt, {"decision": received.decision.value})
        return {
            "applied": applied,
            "validation": None,
            "verification": None,
            "error": None,
            "last_event": "applied",
        }

    @staticmethod
    def _apply_failed(error: str) -> dict[str, Any]:
        return {
            "applied": {"error": error},
            "validation": None,
            "verification": None,
            "error": error,
            "last_event": "apply_failed",
        }

    def validate(self, state: RemediationState) -> dict[str, Any]:
        case_id = state["case_id"]
        attempt = state.get("attempt", 1)
        if self._status(case_id) is CaseStatus.VALIDATION_FAILED:
            recorded = self._audited(case_id, "graph:validate", attempt) or {}
            error = str(recorded.get("error", "validation failed"))
            return {"error": error, "last_event": "validate_failed"}
        self._walk(
            case_id,
            [(CaseStatus.APPLYING, SYSTEM_ACTOR), (CaseStatus.VALIDATING, SYSTEM_ACTOR)],
            {"attempt": attempt, "node": "validate"},
        )
        try:
            validation = self.services.validate(case_id, state.get("applied") or {})
        except GuardianError as exc:
            error = str(exc)
            self._walk(
                case_id,
                [
                    (CaseStatus.VALIDATING, SYSTEM_ACTOR),
                    (CaseStatus.VALIDATION_FAILED, SYSTEM_ACTOR),
                ],
                {"attempt": attempt, "node": "validate", "error": error},
            )
            self._audit_once(case_id, "validate", attempt, {"error": error})
            return {"error": error, "last_event": "validate_failed"}
        self._audit_once(case_id, "validate", attempt)
        return {"validation": validation, "last_event": "validated"}

    def rescan_verify(self, state: RemediationState) -> dict[str, Any]:
        case_id = state["case_id"]
        attempt = state.get("attempt", 1)
        verification = self.services.verify(
            case_id, state.get("applied") or {}, state.get("validation") or {}
        )
        status = verification.get("status")
        target = (
            CaseStatus.VERIFIED
            if status == VerificationStatus.VERIFIED.value
            else CaseStatus.VALIDATION_FAILED
        )
        self._walk(
            case_id,
            [(CaseStatus.VALIDATING, SYSTEM_ACTOR), (target, SYSTEM_ACTOR)],
            {
                "attempt": attempt,
                "node": "rescan_verify",
                "verification": status,
                "reasons": verification.get("reasons", []),
            },
        )
        self._audit_once(case_id, "rescan_verify", attempt, {"verification": status})
        verified = target is CaseStatus.VERIFIED
        return {
            "verification": verification,
            "error": None if verified else f"verification {status}",
            "last_event": "verified" if verified else "verification_failed",
        }

    def publish_failure(self, state: RemediationState) -> dict[str, Any]:
        case_id = state["case_id"]
        attempt = state.get("attempt", 1)
        verification = state.get("verification") or {}
        self._notify_once(
            case_id,
            "failed",
            attempt,
            {
                "reason": state.get("last_event"),
                "error": state.get("error"),
                "verification": verification.get("status"),
                "reasons": verification.get("reasons", []),
            },
        )
        self._walk(
            case_id,
            [
                (CaseStatus.VALIDATION_FAILED, SYSTEM_ACTOR),
                (CaseStatus.AWAITING_DECISION, SYSTEM_ACTOR),
            ],
            {"attempt": attempt, "node": "publish_failure"},
        )
        self._audit_once(case_id, "publish_failure", attempt)
        return {"attempt": attempt + 1, "last_event": "returned_to_review"}

    def record_acceptance(self, state: RemediationState) -> dict[str, Any]:
        case_id = state["case_id"]
        attempt = state.get("attempt", 1)
        decision = HumanDecision.model_validate(state.get("received_decision"))
        self._walk(
            case_id,
            [(CaseStatus.AWAITING_DECISION, SYSTEM_ACTOR), (CaseStatus.DECLINED, _actor(decision))],
            {
                "attempt": attempt,
                "node": "record_acceptance",
                "decline_reason": decision.decline_reason.value
                if decision.decline_reason
                else None,
                "jira_comment_id": decision.jira_comment_id,
            },
        )
        self.services.record_acceptance(case_id, decision)
        self._audit_once(case_id, "record_acceptance", attempt)
        return {"last_event": "declined"}

    def report_back(self, state: RemediationState) -> dict[str, Any]:
        case_id = state["case_id"]
        attempt = state.get("attempt", 1)
        declined = state.get("last_event") == "declined"
        final = CaseStatus.DECLINED if declined else CaseStatus.VERIFIED
        received = state.get("received_decision") or {}
        verification = state.get("verification") or {}
        self._notify_once(
            case_id,
            "declined" if declined else "verified",
            attempt,
            {
                "decline_reason": received.get("decline_reason"),
                "verification": verification.get("status"),
                "risk_before": verification.get("risk_before"),
                "risk_after": verification.get("risk_after"),
                "resolved": verification.get("target_findings_resolved", []),
            },
        )
        self._walk(
            case_id,
            [(final, SYSTEM_ACTOR), (CaseStatus.CLOSED, SYSTEM_ACTOR)],
            {"attempt": attempt, "node": "report_back"},
        )
        self._audit_once(case_id, "report_back", attempt)
        return {"last_event": "closed"}


# --- routing ---------------------------------------------------------------------------------


def _after_decision(state: RemediationState) -> str:
    decision = state.get("received_decision") or {}
    return "record_acceptance" if decision.get("decision") == DecisionType.DECLINE else "apply"


def _after_apply(state: RemediationState) -> str:
    return "publish_failure" if state.get("last_event") == "apply_failed" else "validate"


def _after_validate(state: RemediationState) -> str:
    return "publish_failure" if state.get("last_event") == "validate_failed" else "rescan_verify"


def _after_verify(state: RemediationState) -> str:
    return "report_back" if state.get("last_event") == "verified" else "publish_failure"


def build_remediation_graph(
    db: Database, services: RemediationServices, checkpointer: BaseCheckpointSaver
) -> RemediationGraph:
    """Compile graph B. Run each case on its own thread: ``thread_id = case_id``.

    Nodes run on the calling thread (each step has a single task), which ``Database``'s
    same-thread SQLite connection relies on.
    """
    nodes = _Nodes(db, services)
    # ty does not match a TypedDict class against LangGraph's TypedDictLike protocol.
    graph = StateGraph(RemediationState)  # ty: ignore[invalid-argument-type]
    graph.add_node("plan", nodes.plan)
    graph.add_node("publish_jira", nodes.publish_jira)
    graph.add_node(AWAIT_NODE, nodes.await_decision)
    graph.add_node("apply", nodes.apply)
    graph.add_node("validate", nodes.validate)
    graph.add_node("rescan_verify", nodes.rescan_verify)
    graph.add_node("publish_failure", nodes.publish_failure)
    graph.add_node("record_acceptance", nodes.record_acceptance)
    graph.add_node("report_back", nodes.report_back)
    graph.add_edge(START, "plan")
    graph.add_edge("plan", "publish_jira")
    graph.add_edge("publish_jira", AWAIT_NODE)
    graph.add_conditional_edges(AWAIT_NODE, _after_decision, ["apply", "record_acceptance"])
    graph.add_conditional_edges("apply", _after_apply, ["validate", "publish_failure"])
    graph.add_conditional_edges("validate", _after_validate, ["rescan_verify", "publish_failure"])
    graph.add_conditional_edges("rescan_verify", _after_verify, ["report_back", "publish_failure"])
    graph.add_edge("publish_failure", AWAIT_NODE)
    graph.add_edge("record_acceptance", "report_back")
    graph.add_edge("report_back", END)
    return graph.compile(checkpointer=checkpointer)


# --- drivers ---------------------------------------------------------------------------------


def _config(case_id: str) -> RunnableConfig:
    return {"configurable": {"thread_id": case_id}}


def _interrupt_of(case_id: str, snapshot: StateSnapshot) -> InterruptInfo | None:
    if AWAIT_NODE not in snapshot.next or not snapshot.interrupts:
        return None
    pending = snapshot.interrupts[-1]
    return InterruptInfo(case_id=case_id, interrupt_id=pending.id, payload=dict(pending.value))


def _result(graph: RemediationGraph, case_id: str) -> RunResult:
    snapshot = graph.get_state(_config(case_id))
    return RunResult(
        case_id=case_id,
        values=dict(snapshot.values),
        interrupt=_interrupt_of(case_id, snapshot),
        finished=not snapshot.next and bool(snapshot.values),
    )


def start_case(graph: RemediationGraph, case_id: str) -> InterruptInfo | None:
    """Run a new case thread up to its first interrupt.

    A thread that already exists is never restarted (that would re-plan and re-publish); its
    current interrupt, if any, is returned instead.
    """
    config = _config(case_id)
    snapshot = graph.get_state(config)
    if not snapshot.values and not snapshot.next:
        initial: RemediationState = {
            "case_id": case_id,
            "attempt": 1,
            "decision": None,
            "received_decision": None,
            "applied": None,
            "validation": None,
            "verification": None,
            "jira_key": None,
            "last_event": None,
            "error": None,
        }
        graph.invoke(initial, config, durability=_DURABILITY)
        snapshot = graph.get_state(config)
    return _interrupt_of(case_id, snapshot)


def is_awaiting_decision(graph: RemediationGraph, case_id: str) -> bool:
    return _interrupt_of(case_id, graph.get_state(_config(case_id))) is not None


def resume_case(graph: RemediationGraph, case_id: str, decision: HumanDecision) -> RunResult:
    """Hand a parsed, authorized human decision to the case's paused thread.

    Raises ``ValueError`` for a decision that does not validate or names another case, and
    ``CaseNotAwaitingDecisionError`` when the thread is not paused at ``await_decision``. In both
    cases the thread is left untouched.
    """
    payload = decision.model_dump(mode="json")
    checked = HumanDecision.model_validate(payload)  # ValueError on an inconsistent object
    if checked.case_id != case_id:
        msg = f"Decision is for {checked.case_id}, not {case_id}"
        raise ValueError(msg)
    if not is_awaiting_decision(graph, case_id):
        msg = f"Case {case_id} is not awaiting a decision"
        raise CaseNotAwaitingDecisionError(msg)
    graph.invoke(Command(resume=payload), _config(case_id), durability=_DURABILITY)
    return _result(graph, case_id)


def continue_case(graph: RemediationGraph, case_id: str) -> RunResult:
    """Retry the pending node of a thread that stopped on a crash (not on an interrupt)."""
    snapshot = graph.get_state(_config(case_id))
    if not snapshot.next or _interrupt_of(case_id, snapshot) is not None:
        msg = f"Case {case_id} has no crashed step to retry"
        raise CaseThreadNotResumableError(msg)
    graph.invoke(None, _config(case_id), durability=_DURABILITY)
    return _result(graph, case_id)


def pending_cases(graph: RemediationGraph, case_ids: list[str]) -> list[str]:
    """The subset of ``case_ids`` whose threads are paused waiting for a human."""
    return [case_id for case_id in case_ids if is_awaiting_decision(graph, case_id)]

"""Where a case is in the required flow, as the stations of the route map.

Pure: built from the stored case, decisions, validation runs, verification results and audit
events. The browser only draws what this returns.
"""

from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Literal

from guardian.core.remediation_models import (
    AuditEvent,
    CaseStatus,
    DecisionType,
    HumanDecision,
    RemediationCase,
    StepStatus,
    ValidationRun,
    VerificationResult,
    VerificationStatus,
)

StationState = Literal["done", "current", "failed", "skipped", "pending"]

STATIONS: tuple[tuple[str, str], ...] = (
    ("risk", "Prioritized risk"),
    ("fix", "Recommended fix"),
    ("decision", "Human decision"),
    ("apply", "Applied in isolated branch"),
    ("build", "Build & test (sandboxed)"),
    ("rescan", "Rescan"),
    ("verified", "Verified"),
)
_ORDER = [key for key, _ in STATIONS]

LIVE_STATUSES = frozenset(
    {
        CaseStatus.APPROVED,
        CaseStatus.MODIFICATION_REQUESTED,
        CaseStatus.APPLYING,
        CaseStatus.VALIDATING,
    }
)
_BAD_STEPS = frozenset({StepStatus.FAILED, StepStatus.TIMEOUT})


@dataclass(slots=True)
class Station:
    key: str
    label: str
    state: StationState = "pending"
    at: str | None = None
    note: str | None = None


@dataclass(slots=True)
class Journey:
    stations: list[Station]
    live: bool
    branch: dict[str, str | None] | None = None
    """Set when the case was declined: the terminal spur off the decision station."""
    loop_back: bool = False
    """A validation attempt failed and the case returns (or returned) to human review."""
    failed_attempts: int = 0
    notes: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, object]:
        return asdict(self)


def _last_status_event(events: Sequence[AuditEvent], to: CaseStatus) -> AuditEvent | None:
    suffix = f"->{to.value}"
    matching = [e for e in events if e.event.startswith("status:") and e.event.endswith(suffix)]
    return matching[-1] if matching else None


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _set_through(stations: list[Station], key: str, state: StationState) -> None:
    """Mark every station before ``key`` done and ``key`` itself ``state``."""
    index = _ORDER.index(key)
    for i, station in enumerate(stations):
        if i < index:
            station.state = "done"
        elif i == index:
            station.state = state


def _failed_at(
    events: Sequence[AuditEvent],
    validations: Sequence[ValidationRun],
    verifications: Sequence[VerificationResult],
) -> str:
    applying = _last_status_event(events, CaseStatus.APPLYING)
    failed = _last_status_event(events, CaseStatus.VALIDATION_FAILED)
    if failed is not None and failed.event.startswith(f"status:{CaseStatus.APPLYING.value}->"):
        return "apply"
    since = applying.at if applying is not None else None
    runs = [r for r in validations if since is None or r.started_at >= since]
    if runs and any(step.status in _BAD_STEPS for step in runs[-1].steps):
        return "build"
    if verifications:
        return "rescan"
    return "build"


def _failed_runs(
    validations: Sequence[ValidationRun], verifications: Sequence[VerificationResult]
) -> int:
    bad_runs = sum(1 for r in validations if any(s.status in _BAD_STEPS for s in r.steps))
    bad_verifications = sum(
        1
        for v in verifications
        if v.status in {VerificationStatus.FAILED, VerificationStatus.UNVERIFIED}
    )
    return max(bad_runs, bad_verifications)


def build_journey(  # noqa: C901, PLR0912, PLR0913 - one branch per case status keeps the mapping readable
    case: RemediationCase,
    decisions: Sequence[HumanDecision],
    validations: Sequence[ValidationRun],
    verifications: Sequence[VerificationResult],
    events: Sequence[AuditEvent],
    *,
    decision_pending: bool = False,
) -> Journey:
    stations = [Station(key, label) for key, label in STATIONS]
    by_key = {s.key: s for s in stations}
    status = case.status
    last_decision = decisions[-1] if decisions else None

    # Timestamps from the record, whichever stage has been reached.
    by_key["risk"].at = _iso(case.created_at)
    if (awaiting := _last_status_event(events, CaseStatus.AWAITING_DECISION)) is not None:
        by_key["fix"].at = _iso(awaiting.at)
    if last_decision is not None:
        by_key["decision"].at = _iso(last_decision.decided_at)
        by_key["decision"].note = f"{last_decision.decision.value.lower()} by " + (
            last_decision.actor_display
        )
    if (applying := _last_status_event(events, CaseStatus.APPLYING)) is not None:
        by_key["apply"].at = _iso(applying.at)
    if (validating := _last_status_event(events, CaseStatus.VALIDATING)) is not None:
        by_key["build"].at = _iso(validating.at)
    if validations and validations[-1].finished_at is not None:
        by_key["rescan"].at = _iso(validations[-1].finished_at)
    if (verified := _last_status_event(events, CaseStatus.VERIFIED)) is not None:
        by_key["verified"].at = _iso(verified.at)
    if validations:
        by_key["apply"].note = validations[-1].branch

    journey = Journey(
        stations=stations,
        live=status in LIVE_STATUSES or decision_pending,
        failed_attempts=_failed_runs(validations, verifications),
    )
    declined = last_decision is not None and last_decision.decision is DecisionType.DECLINE

    if status is CaseStatus.PROPOSED:
        _set_through(stations, "fix", "current")
    elif status is CaseStatus.AWAITING_DECISION:
        _set_through(stations, "decision", "current")
        journey.loop_back = journey.failed_attempts > 0
    elif status in {CaseStatus.APPROVED, CaseStatus.MODIFICATION_REQUESTED, CaseStatus.APPLYING}:
        _set_through(stations, "apply", "current")
    elif status is CaseStatus.VALIDATING:
        since = applying.at if applying is not None else None
        finished = [
            r
            for r in validations
            if r.finished_at is not None and (since is None or r.started_at >= since)
        ]
        _set_through(stations, "rescan" if finished else "build", "current")
    elif status is CaseStatus.VALIDATION_FAILED:
        _set_through(stations, _failed_at(events, validations, verifications), "failed")
        journey.loop_back = True
    elif status is CaseStatus.VERIFIED or (status is CaseStatus.CLOSED and not declined):
        _set_through(stations, "verified", "done")
    elif status in {CaseStatus.DECLINED, CaseStatus.CLOSED}:
        _set_through(stations, "decision", "done")
        for station in stations[_ORDER.index("decision") + 1 :]:
            station.state = "skipped"
        reason = last_decision.decline_reason if last_decision is not None else None
        expires = last_decision.risk_acceptance_expires if last_decision is not None else None
        journey.branch = {
            "reason": reason.value if reason is not None else None,
            "until": expires.isoformat() if expires is not None else None,
            "justification": last_decision.justification if last_decision is not None else None,
        }

    if verifications:
        latest = verifications[-1]
        if latest.status is not VerificationStatus.VERIFIED:  # "Verified: verified" says nothing
            by_key["verified"].note = latest.status.value.replace("_", " ").lower()
    if decision_pending and status is CaseStatus.AWAITING_DECISION:
        journey.notes.append("Decision recorded; Guardian is moving the case on.")
    return journey

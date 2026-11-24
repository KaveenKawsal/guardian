"""Remediation data models: candidates, plans, human decisions, validation and audit.

Everything is frozen like the rest of ``core/models.py``. A remediation case changes state by
``RemediationCase.transition`` returning a new copy; the allowed edges live in
``ALLOWED_TRANSITIONS``. Fields that carry LLM output are labelled with ``source``.
"""

import hashlib
import json
from datetime import UTC, date, datetime
from enum import StrEnum
from typing import Literal, Self

from pydantic import BaseModel, Field, model_validator

from guardian.core.exceptions import IllegalTransitionError
from guardian.core.models import Confidence, Priority, _Frozen

Source = Literal["verified", "inferred"]
"""``verified``: established by a deterministic tool. ``inferred``: produced by an LLM."""


# --- Identifiers -----------------------------------------------------------------------

_ID_SEPARATOR = "\x1f"  # ASCII unit separator: no field can run into its neighbour


def _sha1(*parts: str) -> str:
    return hashlib.sha1(
        _ID_SEPARATOR.join(parts).encode("utf-8"), usedforsecurity=False
    ).hexdigest()


def fingerprint_for(repo_root: str, component: str, vuln_or_rule: str) -> str:
    """Stable case fingerprint: sha1 over repository root, component purl/path and vuln/rule id."""
    return _sha1(repo_root, component, vuln_or_rule)


def case_id_for(fingerprint: str) -> str:
    """``rc_<12 hex>``; deterministic so a rescan finds the same case."""
    return f"rc_{fingerprint[:12]}"


def candidate_id_for(
    fingerprint: str, action_type: "RemediationActionType", component: str, to_version: str | None
) -> str:
    """``cand_<12 hex>`` over the case fingerprint, action, component and target version."""
    return f"cand_{_sha1(fingerprint, action_type.value, component, to_version or '')[:12]}"


def jira_label_for(fingerprint: str) -> str:
    return f"guardian-fp-{fingerprint[:16]}"


def canonical_json(obj: object) -> str:
    """Deterministic JSON: sorted keys, no whitespace, non-JSON values via ``str``."""
    if isinstance(obj, BaseModel):
        obj = obj.model_dump(mode="json")
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def audit_event_hash(  # noqa: PLR0913, PLR0917 - one argument per chained field
    prev_event_sha256: str | None,
    case_id: str | None,
    event: str,
    actor: str,
    at: str,
    payload_sha256: str,
) -> str:
    """Chain hash of one audit event. ``at`` is the stored ISO-8601 string."""
    fields = [prev_event_sha256 or "", case_id or "", event, actor, at, payload_sha256]
    return sha256_hex(_ID_SEPARATOR.join(fields))


# --- Candidates and plans --------------------------------------------------------------


class RemediationActionType(StrEnum):
    UPGRADE = "UPGRADE"
    PIN = "PIN"
    REPLACE = "REPLACE"
    REMOVE = "REMOVE"
    UPDATE_BASE_IMAGE = "UPDATE_BASE_IMAGE"
    BLOCK = "BLOCK"
    """Add the component to a Guardian policy denylist; no code change."""
    ESCALATE = "ESCALATE"
    """Hand the case to a human owner; no code change."""


class SemverJump(StrEnum):
    PATCH = "patch"
    MINOR = "minor"
    MAJOR = "major"
    UNKNOWN = "unknown"


class RemediationCandidate(_Frozen):
    """One deterministic fix option. The LLM may only pick among these by ``id``."""

    id: str
    case_id: str
    finding_ids: list[str] = Field(default_factory=list)
    action_type: RemediationActionType
    component: str = Field(description="purl, or repository-relative path for files")
    from_version: str | None = None
    to_version: str | None = None
    manifest_path: str | None = None
    lockfile_path: str | None = None
    fixes_finding_ids: list[str] = Field(default_factory=list)
    semver_jump: SemverJump = SemverJump.UNKNOWN
    compatibility_notes: list[str] = Field(
        default_factory=list, description="Verified facts only: changelog entries, major bumps"
    )
    rollback: str = Field(description="Exact git command or revert instructions")
    expected_risk_reduction: float | None = Field(
        default=None, description="Risk score points removed when the targeted findings resolve"
    )
    version_verified: bool | None = Field(
        default=None,
        description="Registry confirmed to_version exists; False = unverified_version, "
        "None = not applicable",
    )
    evidence: list[str] = Field(default_factory=list)
    strategy: Literal["direct", "parent", "override"] | None = Field(
        default=None,
        description="npm: edit the package's own entry, upgrade the direct parent that pulls "
        "it in, or force it through package.json overrides; None for non-version actions",
    )
    target_package: str | None = Field(
        default=None,
        description="Package whose manifest entry changes (parent strategy); from/to_version "
        "then refer to it",
    )
    source: Literal["verified"] = "verified"


class RemediationPlan(_Frozen):
    case_id: str
    chosen_candidate_id: str
    alternatives: list[str] = Field(default_factory=list, description="Other candidate IDs")
    rationale: str
    confidence: Confidence
    llm_provider: str | None = None
    llm_model: str | None = None
    source: Source = Field(description="inferred when an LLM chose; verified for --no-ai")
    decided_by: Literal["llm", "deterministic"]
    notes: list[str] = Field(
        default_factory=list, description="e.g. 'ai_unavailable: <reason>' when AI fell back"
    )

    @model_validator(mode="after")
    def _source_matches_decider(self) -> Self:
        expected = "inferred" if self.decided_by == "llm" else "verified"
        if self.source != expected:
            msg = f"A plan decided by {self.decided_by} must have source={expected!r}"
            raise ValueError(msg)
        return self


# --- Human decisions -------------------------------------------------------------------


class DecisionType(StrEnum):
    ACCEPT = "ACCEPT"
    MODIFY = "MODIFY"
    DECLINE = "DECLINE"
    REVALIDATE = "REVALIDATE"


class DeclineReason(StrEnum):
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    WONT_FIX = "WONT_FIX"
    DUPLICATE = "DUPLICATE"


class ModifyPayload(_Frozen):
    """Exactly one kind: another candidate, a version, an action (optionally with a target),
    or a branch/commit the human prepared themselves."""

    candidate_id: str | None = None
    version: str | None = None
    action: RemediationActionType | None = None
    target: str | None = Field(default=None, description="purl; only together with action")
    branch: str | None = None
    commit: str | None = None

    @property
    def kind(self) -> str:
        for name in ("candidate_id", "version", "action", "branch", "commit"):
            if getattr(self, name) is not None:
                return name
        return "none"  # unreachable after validation

    @model_validator(mode="after")
    def _exactly_one_kind(self) -> Self:
        kinds = [
            name
            for name in ("candidate_id", "version", "action", "branch", "commit")
            if getattr(self, name) is not None
        ]
        if len(kinds) != 1:
            msg = (
                "A modification needs exactly one of candidate_id, version, action, branch, "
                f"commit; got {kinds or 'none'}"
            )
            raise ValueError(msg)
        if self.target is not None and self.action is None:
            msg = "target= is only valid together with action="
            raise ValueError(msg)
        return self


class HumanDecision(_Frozen):
    case_id: str
    decision: DecisionType
    candidate_id: str | None = Field(default=None, description="accept candidate=<id>")
    modify: ModifyPayload | None = None
    decline_reason: DeclineReason | None = None
    risk_acceptance_expires: date | None = None
    justification: str | None = None
    actor_id: str
    actor_display: str
    channel: Literal["jira", "cli"]
    jira_comment_id: str | None = None
    decided_at: datetime

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.decision is DecisionType.MODIFY and self.modify is None:
            msg = "A MODIFY decision needs a modify payload"
            raise ValueError(msg)
        if self.decision is not DecisionType.MODIFY and self.modify is not None:
            msg = "Only a MODIFY decision carries a modify payload"
            raise ValueError(msg)
        if self.decision is DecisionType.DECLINE and self.decline_reason is None:
            msg = "A DECLINE decision needs a decline_reason"
            raise ValueError(msg)
        if self.decision is not DecisionType.DECLINE and self.decline_reason is not None:
            msg = "Only a DECLINE decision carries a decline_reason"
            raise ValueError(msg)
        if self.decline_reason is DeclineReason.ACCEPTED_RISK and (
            self.risk_acceptance_expires is None or not (self.justification or "").strip()
        ):
            msg = "accepted_risk requires an expiry date (until=) and a justification"
            raise ValueError(msg)
        if self.candidate_id is not None and self.decision is not DecisionType.ACCEPT:
            msg = "candidate_id is only valid on ACCEPT; use modify candidate_id otherwise"
            raise ValueError(msg)
        return self


# --- Validation and verification -------------------------------------------------------


class StepStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"
    NOT_FOUND = "not_found"
    """Nothing to run, e.g. no tests discovered."""


class ValidationStep(_Frozen):
    name: Literal["install", "build", "test"]
    status: StepStatus
    exit_code: int | None = None
    duration_seconds: float = 0.0
    log_path: str | None = None
    detail: str | None = None
    known_conflict: bool = Field(
        default=False,
        description="Test failures confined to expected challenge-code tests (e.g. Juice Shop "
        "rsn.unit.test.ts): the fix conflicts with intentional training code",
    )


class ValidationRun(_Frozen):
    case_id: str
    branch: str
    worktree_path: str
    commit_sha: str | None = None
    sandbox: Literal["docker", "none", "host-unsafe"]
    steps: list[ValidationStep] = Field(default_factory=list)
    tests_discovered: int | None = None
    tests_passed: int | None = None
    tests_failed: int | None = None
    started_at: datetime
    finished_at: datetime | None = None


class VerificationStatus(StrEnum):
    VERIFIED = "VERIFIED"
    PARTIALLY_VERIFIED = "PARTIALLY_VERIFIED"
    FAILED = "FAILED"
    UNVERIFIED = "UNVERIFIED"


class ComponentChange(_Frozen):
    purl_base: str = Field(description="purl without the version")
    from_version: str | None = None
    to_version: str | None = None


class SbomDiff(_Frozen):
    added: list[str] = Field(default_factory=list, description="purls")
    removed: list[str] = Field(default_factory=list, description="purls")
    changed: list[ComponentChange] = Field(default_factory=list)


class VerificationResult(_Frozen):
    case_id: str
    before_scan_id: str
    after_scan_id: str | None = None
    target_findings_resolved: list[str] = Field(default_factory=list)
    findings_still_present: list[str] = Field(default_factory=list)
    new_findings: list[str] = Field(default_factory=list)
    sbom_diff: SbomDiff = Field(default_factory=SbomDiff)
    risk_before: float | None = None
    risk_after: float | None = None
    status: VerificationStatus
    confidence: Confidence
    reasons: list[str] = Field(default_factory=list)


# --- Cases and the state machine -------------------------------------------------------


class CaseStatus(StrEnum):
    PROPOSED = "PROPOSED"
    AWAITING_DECISION = "AWAITING_DECISION"
    DECLINED = "DECLINED"
    APPROVED = "APPROVED"
    MODIFICATION_REQUESTED = "MODIFICATION_REQUESTED"
    APPLYING = "APPLYING"
    VALIDATING = "VALIDATING"
    VERIFIED = "VERIFIED"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    CLOSED = "CLOSED"


ALLOWED_TRANSITIONS: dict[CaseStatus, frozenset[CaseStatus]] = {
    CaseStatus.PROPOSED: frozenset({CaseStatus.AWAITING_DECISION}),
    CaseStatus.AWAITING_DECISION: frozenset(
        {CaseStatus.DECLINED, CaseStatus.APPROVED, CaseStatus.MODIFICATION_REQUESTED}
    ),
    CaseStatus.APPROVED: frozenset({CaseStatus.APPLYING}),
    CaseStatus.MODIFICATION_REQUESTED: frozenset({CaseStatus.APPLYING}),
    # APPLYING -> VALIDATION_FAILED covers a patch that cannot be applied.
    CaseStatus.APPLYING: frozenset({CaseStatus.VALIDATING, CaseStatus.VALIDATION_FAILED}),
    CaseStatus.VALIDATING: frozenset({CaseStatus.VERIFIED, CaseStatus.VALIDATION_FAILED}),
    CaseStatus.VALIDATION_FAILED: frozenset({CaseStatus.AWAITING_DECISION}),
    CaseStatus.VERIFIED: frozenset({CaseStatus.CLOSED}),
    CaseStatus.DECLINED: frozenset({CaseStatus.CLOSED}),
    CaseStatus.CLOSED: frozenset(),
}


class RemediationCase(_Frozen):
    id: str
    fingerprint: str
    scan_id: str
    repository_root: str
    finding_ids: list[str] = Field(default_factory=list)
    title: str
    priority: Priority
    status: CaseStatus = CaseStatus.PROPOSED
    created_at: datetime
    updated_at: datetime
    jira_key: str | None = None

    def can_transition(self, to: CaseStatus) -> bool:
        return to in ALLOWED_TRANSITIONS[self.status]

    def transition(self, to: CaseStatus, at: datetime | None = None) -> "RemediationCase":
        """Return a copy in state ``to``; raise ``IllegalTransitionError`` on a disallowed edge."""
        if not self.can_transition(to):
            msg = f"Case {self.id}: {self.status.value} -> {to.value} is not an allowed transition"
            raise IllegalTransitionError(msg)
        return self.model_copy(update={"status": to, "updated_at": at or datetime.now(UTC)})


class JiraLink(_Frozen):
    case_id: str
    issue_key: str
    fingerprint: str
    last_synced_comment_id: str | None = None
    updated_at: datetime


class AuditEvent(_Frozen):
    """One entry of the global, append-only, hash-chained audit log."""

    id: int | None = None
    case_id: str | None = None
    event: str = Field(description="e.g. 'case:created', 'status:APPROVED->APPLYING'")
    actor: str
    at: datetime
    payload_json: str = Field(description="canonical_json(payload)")
    payload_sha256: str
    prev_event_sha256: str | None = None
    event_sha256: str

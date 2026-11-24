"""Data models of the AI investigators (Milestone 8).

Two kinds of model live here:

* ``*Answer`` models are the structured output requested from the chat model. Every claim
  carries ``evidence_refs`` that must name IDs present in the agent's input (rule 7); claims
  whose refs are unknown are stripped before anything is stored.
* ``*Assessment`` models are the stored, validated answers. They add
  ``source: Literal["inferred"]`` so every AI statement is labelled as inference (rule 10).

``InvestigatorReport`` wraps one agent's result for one subject: the deterministic
``verified_facts`` it was given (copied, never generated) and, when the model answered, the
validated assessment. When AI is off, over budget or failed, ``status`` is ``ai_unavailable``
and only the verified facts are present.

The investigators interpret; they never decide whether a version is vulnerable, never change a
severity or fix version, and never decide anything a human must decide (rule 6).
"""

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from guardian.core.models import Confidence

AgentName = Literal["architect", "dependency", "vulnerability", "code", "correlator"]
SubjectKind = Literal["case", "finding", "scan"]
ReportStatus = Literal["ok", "repaired", "ai_unavailable"]
Role = Literal["fast", "deep"]
Relevance = Literal["likely", "possible", "unlikely", "unknown"]
AreaKind = Literal["prod", "dev", "test", "challenge-fixture", "unknown"]

AGENTS: tuple[AgentName, ...] = ("architect", "dependency", "vulnerability", "code", "correlator")
AGENT_LABELS: dict[str, str] = {
    "architect": "Repository Architect",
    "dependency": "Dependency Investigator",
    "vulnerability": "Vulnerability Investigator",
    "code": "Code Investigator",
    "correlator": "Evidence Correlator",
}
AGENT_ROLES: dict[str, Role] = {
    "architect": "deep",
    "dependency": "fast",
    "vulnerability": "fast",
    "code": "fast",
    "correlator": "deep",
}

MAX_TEXT = 1200
MAX_CLAIMS = 8


class _Answer(BaseModel):
    model_config = ConfigDict(extra="ignore")


class Claim(_Answer):
    """One statement plus the input IDs it rests on."""

    text: str = Field(description="One or two sentences.", max_length=MAX_TEXT)
    evidence_refs: list[str] = Field(
        default_factory=list,
        description="IDs copied exactly from the 'refs' given in the data block.",
    )


# --- Repository Architect ----------------------------------------------------------------


class ModuleNote(_Answer):
    area: str = Field(description="An area name exactly as listed in the data block.")
    purpose: str = Field(description="What this area does, one sentence.", max_length=MAX_TEXT)
    kind: AreaKind = Field(description="prod, dev, test, challenge-fixture or unknown.")
    evidence_refs: list[str] = Field(default_factory=list)


class ArchitectAnswer(_Answer):
    modules: list[ModuleNote] = Field(default_factory=list)
    key_entry_points: list[Claim] = Field(
        default_factory=list, description="The entry points that matter most for attackers."
    )
    notes: list[Claim] = Field(default_factory=list)


class ArchitectAssessment(ArchitectAnswer):
    source: Literal["inferred"] = "inferred"


# --- Dependency Investigator -------------------------------------------------------------


class DependencyAnswer(_Answer):
    how_it_enters: Claim = Field(description="How the package enters the dependency tree.")
    scope_assessment: Literal["prod", "dev", "unknown"] = Field(
        description="Whether the package is used by production code."
    )
    scope_reasons: list[Claim] = Field(default_factory=list)
    blast_radius: Claim = Field(description="Which code and features depend on it.")


class DependencyAssessment(DependencyAnswer):
    source: Literal["inferred"] = "inferred"


# --- Vulnerability Investigator ----------------------------------------------------------


class VulnerabilityAnswer(_Answer):
    """Brocards 1-3 and 7 as fields: a threat model, the prerequisites an attacker needs,
    whether the vulnerable behaviour is reached by real usage, and what is still unknown.
    Relevance is an opinion about *this repository*; it never changes the verified facts."""

    relevance: Relevance = Field(
        description="How likely the advisory matters for THIS repository's usage."
    )
    threat_model: Claim = Field(
        description="An attacker with [capability] can [action] to achieve [impact]."
    )
    reasons: list[Claim] = Field(default_factory=list)
    prerequisites: list[Claim] = Field(
        default_factory=list, description="Conditions that must hold for exploitation."
    )
    open_questions: list[str] = Field(
        default_factory=list, description="What a human should check; no evidence needed."
    )


class VulnerabilityAssessment(VulnerabilityAnswer):
    source: Literal["inferred"] = "inferred"


# --- Code Investigator -------------------------------------------------------------------


class CodeAnswer(_Answer):
    """fp-check, standard path: restate the claim, trace source to sink, then argue against it."""

    exploitability: Relevance = Field(description="likely, possible, unlikely or unknown.")
    narrative: Claim = Field(description="What the flagged code does and why it matters.")
    input_path: list[Claim] = Field(
        default_factory=list,
        description="Attacker-controlled input to the flagged line, one step per claim.",
    )
    counter_evidence: list[Claim] = Field(
        default_factory=list,
        description="Validation, sanitisation or context that argues against exploitability.",
    )
    intentional_challenge_code: bool = Field(
        description="True when the code looks like a deliberate training vulnerability."
    )
    intentional_reason: Claim | None = None


class CodeAssessment(CodeAnswer):
    source: Literal["inferred"] = "inferred"


# --- Evidence Correlator -----------------------------------------------------------------


class CorrelatorAnswer(_Answer):
    assessment: Claim = Field(description="Guardian's overall reading of this item.")
    confidence: Confidence
    recommendation: str | None = Field(
        default=None, description="Optional next step for the reviewer.", max_length=MAX_TEXT
    )
    recommended_candidate_id: str | None = Field(
        default=None, description="Only an id from the listed candidates, or null."
    )


class CorrelatorAssessment(CorrelatorAnswer):
    source: Literal["inferred"] = "inferred"


ANSWER_MODELS: dict[str, type[_Answer]] = {
    "architect": ArchitectAnswer,
    "dependency": DependencyAnswer,
    "vulnerability": VulnerabilityAnswer,
    "code": CodeAnswer,
    "correlator": CorrelatorAnswer,
}
ASSESSMENT_MODELS: dict[str, type[_Answer]] = {
    "architect": ArchitectAssessment,
    "dependency": DependencyAssessment,
    "vulnerability": VulnerabilityAssessment,
    "code": CodeAssessment,
    "correlator": CorrelatorAssessment,
}


# --- Stored records ----------------------------------------------------------------------


class Fact(BaseModel):
    """A verified fact copied from deterministic tool output."""

    model_config = ConfigDict(frozen=True)

    label: str
    value: str
    ref: str | None = None
    source: Literal["verified"] = "verified"


class CallRecord(BaseModel):
    """One LLM call (or attempt)."""

    agent: str
    subject_id: str
    role: Role
    provider: str
    model: str
    key_index: int | None = None
    """Position in the provider's key pool (0 = primary key); never the key itself."""
    attempt: int = 1
    latency_seconds: float = 0.0
    input_chars: int = 0
    input_tokens: int | None = None
    output_tokens: int | None = None
    status: Literal["ok", "rejected", "error", "rate_limited"] = "ok"
    error: str | None = None


class InvestigatorReport(BaseModel):
    agent: AgentName
    subject_kind: SubjectKind
    subject_id: str
    title: str = ""
    status: ReportStatus
    source: Literal["inferred", "verified"] = Field(
        default="inferred",
        description="'verified' when no AI output is present (ai_unavailable fallback).",
    )
    verified_facts: list[Fact] = Field(default_factory=list)
    assessment: dict[str, Any] | None = Field(
        default=None, description="The validated *Assessment model dump, or None."
    )
    dropped_refs: list[str] = Field(
        default_factory=list, description="Evidence refs the model gave that were not in input."
    )
    dropped_claims: int = 0
    reason: str | None = Field(default=None, description="Why AI output is missing, if it is.")
    provider: str | None = None
    model: str | None = None
    latency_seconds: float | None = None
    finding_ids: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class TraceEvent(BaseModel):
    node: str
    event: Literal["started", "finished"]
    at: datetime
    agent: str | None = None
    subject_id: str | None = None
    status: str | None = None
    detail: str | None = None


class InvestigationRun(BaseModel):
    id: str
    scan_id: str
    started_at: datetime
    finished_at: datetime | None = None
    status: Literal["running", "completed", "partial", "failed"] = "running"
    ai_enabled: bool = True
    max_calls: int = 0
    provider_calls: list[CallRecord] = Field(default_factory=list)
    trace: list[TraceEvent] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

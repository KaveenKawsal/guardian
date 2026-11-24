"""Report data model: everything a human reviewer needs, assembled once per scan.

CONTRACT shared by the report builder (``report_data.py``), the renderers (``render.py``)
and the interactive shell. All text originates from scanned repositories, scanners or
advisories and is untrusted: renderers must escape it.
"""

from datetime import date, datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from guardian.core.models import (
    EntryPoint,
    Finding,
    Priority,
    RiskAssessment,
    ScanRecord,
    Severity,
    ToolRunSummary,
)
from guardian.core.remediation_models import (
    HumanDecision,
    RemediationCandidate,
    RemediationCase,
    RemediationPlan,
    ValidationRun,
    VerificationResult,
    VerificationStatus,
)
from guardian.indexing.code_retriever import CodeSnippet

REPORT_SCHEMA_VERSION = "2"
"""2: adds the optional top-level ``remediation`` section (absent when the scan has no cases)."""


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ReportFormat(StrEnum):
    HTML = "html"
    MARKDOWN = "md"
    JSON = "json"


class ReportFinding(_Frozen):
    finding: Finding
    risk: RiskAssessment
    code: list[CodeSnippet] = Field(default_factory=list, description="Redacted source context")
    introduction_paths: list[list[str]] = Field(
        default_factory=list, description="Dependency chains, e.g. [['express@4', 'qs@6']]"
    )
    remediation: str = Field(description="Concrete next step for a human")


class SeverityCount(_Frozen):
    severity: Severity
    count: int


class PriorityCount(_Frozen):
    priority: Priority
    count: int


class PackageRisk(_Frozen):
    """A vulnerable package, aggregated over its findings."""

    package: str
    version: str | None
    ecosystem: str | None
    direct: bool | None
    used_in_code: bool | None = Field(description="Imported by the indexed source; None = unknown")
    vulnerability_count: int
    worst_severity: Severity
    recommended_fix: str | None


class ReportSummary(_Frozen):
    headline: str = Field(description="One-sentence overall assessment")
    total_findings: int
    by_severity: list[SeverityCount]
    by_priority: list[PriorityCount]
    by_kind: dict[str, int]
    components: int
    direct_dependencies: int
    vulnerable_packages: int
    vulnerable_packages_used_in_code: int
    files_indexed: int
    entry_points: int


class ReportMeta(_Frozen):
    schema_version: str = REPORT_SCHEMA_VERSION
    guardian_version: str
    generated_at: datetime
    repository: str
    source: str = Field(description="Local path or remote display name, e.g. github.com/o/r")
    scan: ScanRecord
    ai_used: bool = False


# --- Remediation (schema 2) -------------------------------------------------------------


class AiStatement(_Frozen):
    """One statement of an AI investigator. Always inference, never a verified fact."""

    label: str
    text: str
    evidence_refs: list[str] = Field(default_factory=list)


class ReportInvestigation(_Frozen):
    """One AI investigator's assessment of a case or one of its findings."""

    agent: str
    agent_label: str
    subject_kind: str
    subject_id: str
    status: str
    provider: str | None = None
    model: str | None = None
    created_at: datetime
    statements: list[AiStatement] = Field(default_factory=list)
    source: Literal["inferred"] = "inferred"


class ReportDecision(_Frozen):
    decision: HumanDecision
    jira_key: str | None = None
    jira_url: str | None = None
    expired: bool | None = Field(
        default=None, description="Accepted risk past its expiry date; None = no expiry"
    )


class AcceptedRisk(_Frozen):
    expires: date
    expired: bool
    justification: str | None
    actor_display: str
    decided_at: datetime


class ReportAuditEvent(_Frozen):
    id: int | None
    event: str
    actor: str
    at: datetime
    payload_sha256: str
    event_sha256: str


class AuditChainStatus(_Frozen):
    ok: bool
    events: int
    problems: list[str] = Field(default_factory=list)


class RemediationCaseReport(_Frozen):
    case: RemediationCase
    jira_url: str | None = None
    findings: list[Finding] = Field(
        default_factory=list, description="The case's findings as recorded by the scanners"
    )
    missing_finding_ids: list[str] = Field(
        default_factory=list, description="Case finding ids not stored with any loaded scan"
    )
    investigations: list[ReportInvestigation] = Field(default_factory=list)
    recommended: RemediationCandidate | None = None
    alternatives: list[RemediationCandidate] = Field(default_factory=list)
    plan: RemediationPlan | None = None
    decisions: list[ReportDecision] = Field(default_factory=list)
    accepted_risk: AcceptedRisk | None = None
    validations: list[ValidationRun] = Field(default_factory=list)
    verifications: list[VerificationResult] = Field(default_factory=list)
    verdict: VerificationStatus | None = Field(
        default=None, description="Status of the latest verification"
    )
    risk_before: float | None = None
    risk_after: float | None = None
    pull_request_url: str | None = None
    audit: list[ReportAuditEvent] = Field(default_factory=list)


class RemediationSection(_Frozen):
    cases: list[RemediationCaseReport]
    audit_chain: AuditChainStatus


class ReportData(_Frozen):
    meta: ReportMeta
    summary: ReportSummary
    findings: list[ReportFinding] = Field(description="Sorted: priority, then risk score")
    packages: list[PackageRisk] = Field(default_factory=list)
    entry_points: list[EntryPoint] = Field(default_factory=list)
    tool_runs: list[ToolRunSummary] = Field(default_factory=list)
    limitations: list[str] = Field(
        default_factory=list,
        description="What the reviewer should know: skipped tools, partial data, heuristics",
    )
    remediation: RemediationSection | None = Field(
        default=None, description="Remediation cases for this scan; omitted when there are none"
    )


def report_payload(report: ReportData) -> dict:
    """The JSON form of a report; ``remediation`` is left out entirely when there is none."""
    payload = report.model_dump(mode="json")
    if payload.get("remediation") is None:
        payload.pop("remediation", None)
    return payload

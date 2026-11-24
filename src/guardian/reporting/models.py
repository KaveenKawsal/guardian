"""Report data model: everything a human reviewer needs, assembled once per scan.

CONTRACT shared by the report builder (``report_data.py``), the renderers (``render.py``)
and the interactive shell. All text originates from scanned repositories, scanners or
advisories and is untrusted: renderers must escape it.
"""

from datetime import datetime
from enum import StrEnum

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
from guardian.indexing.code_retriever import CodeSnippet

REPORT_SCHEMA_VERSION = "1"


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

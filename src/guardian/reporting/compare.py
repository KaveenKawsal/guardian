"""Before/after comparison of two stored scans: SBOM, findings and risk.

Deterministic: SBOM and finding differences come from ``remediation.diff`` and risk scores
from ``knowledge.risk`` over each scan's own dependency graph and code index.
"""

from collections import Counter
from collections.abc import Iterable
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from guardian.core.models import (
    Finding,
    Priority,
    RiskAssessment,
    Sbom,
    ScanRecord,
    Severity,
)
from guardian.core.remediation_models import SbomDiff
from guardian.knowledge.graph_builder import build_knowledge_graph
from guardian.knowledge.graph_queries import DependencyGraph
from guardian.knowledge.risk import assess
from guardian.remediation.diff import diff_findings, diff_sboms
from guardian.storage.database import Database

ComparisonStatus = Literal["improved", "regressed", "mixed", "unchanged"]


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ScanRisk(_Frozen):
    scan: ScanRecord
    findings: int
    components: int
    max_score: float | None = Field(description="Highest risk score; None without scored findings")
    total_score: float = Field(description="Sum of all known risk scores")
    by_priority: dict[str, int]


class ComparedFinding(_Frozen):
    id: str
    title: str
    severity: Severity
    kind: str
    score: float | None
    priority: Priority


class ScanComparison(_Frozen):
    before: ScanRisk
    after: ScanRisk
    status: ComparisonStatus
    sbom_diff: SbomDiff
    resolved: list[ComparedFinding] = Field(description="In the first scan only")
    still_present: list[ComparedFinding] = Field(description="In both scans (scored as after)")
    new: list[ComparedFinding] = Field(description="In the second scan only")


def scan_risks(db: Database, scan_id: str) -> tuple[list[Finding], list[RiskAssessment]]:
    """The scan's findings and their risk, assessed the same way as the report does."""
    profile = db.scans.profile(scan_id)
    sbom = db.sboms.load(scan_id)
    findings = db.findings.load(scan_id)
    changes = db.findings.changes(scan_id)
    index = db.code.load(scan_id)
    graph = DependencyGraph(
        build_knowledge_graph(profile, sbom, findings, changes, code_index=index)
    )
    return findings, assess(findings, graph, index)


def compare_scans(db: Database, before_id: str, after_id: str) -> ScanComparison:
    """Raises ``ScanNotFoundError`` for unknown scan ids (resolve prefixes first)."""
    before_findings, before_risks = scan_risks(db, before_id)
    after_findings, after_risks = scan_risks(db, after_id)
    before_sbom, after_sbom = db.sboms.load(before_id), db.sboms.load(after_id)
    resolved, still, new = diff_findings(before_findings, after_findings)
    old = _compared(before_findings, before_risks)
    current = _compared(after_findings, after_risks)
    return ScanComparison(
        before=_scan_risk(db.scans.get(before_id), before_risks, before_sbom),
        after=_scan_risk(db.scans.get(after_id), after_risks, after_sbom),
        status=_status(len(resolved), len(new)),
        sbom_diff=diff_sboms(before_sbom, after_sbom),
        resolved=_ordered(old[i] for i in resolved),
        still_present=_ordered(current[i] for i in still),
        new=_ordered(current[i] for i in new),
    )


def _status(resolved: int, new: int) -> ComparisonStatus:
    if resolved and new:
        return "mixed"
    if resolved:
        return "improved"
    if new:
        return "regressed"
    return "unchanged"


def _compared(findings: list[Finding], risks: list[RiskAssessment]) -> dict[str, ComparedFinding]:
    return {
        f.id: ComparedFinding(
            id=f.id,
            title=f.title,
            severity=f.severity,
            kind=f.kind.value,
            score=r.score,
            priority=r.priority,
        )
        for f, r in zip(findings, risks, strict=True)
    }


def _ordered(items: Iterable[ComparedFinding]) -> list[ComparedFinding]:
    return sorted(items, key=lambda f: (-(f.score or -1.0), -f.severity.rank, f.title, f.id))


def _scan_risk(record: ScanRecord, risks: list[RiskAssessment], sbom: Sbom | None) -> ScanRisk:
    scores = [r.score for r in risks if r.score is not None]
    priorities = Counter(r.priority for r in risks)
    return ScanRisk(
        scan=record,
        findings=len(risks),
        components=len(sbom.components) if sbom else 0,
        max_score=max(scores) if scores else None,
        total_score=round(sum(scores), 2),
        by_priority={p.value: priorities[p] for p in Priority},
    )

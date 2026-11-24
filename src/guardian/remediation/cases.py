"""Turn a stored scan into remediation cases: one case per vulnerable npm package.

``create_cases`` is idempotent by case fingerprint. A case still waiting for a human
(PROPOSED / AWAITING_DECISION) is pointed at the new scan (``refresh_case``) and gets a fresh
candidate set (``replace_candidates``: stale candidate ids disappear, audited) and a fresh
plan; a case in any later state is left untouched, so a rescan never overrides a recorded
decision. Every step is audited.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from langchain_core.language_models import BaseChatModel

from guardian.core.config import GuardianSettings
from guardian.core.models import Finding, Priority, RiskAssessment, VulnerabilityDetails
from guardian.core.remediation_models import (
    CaseStatus,
    RemediationCase,
    case_id_for,
    fingerprint_for,
)
from guardian.knowledge.graph_builder import build_knowledge_graph
from guardian.knowledge.graph_queries import DependencyGraph
from guardian.knowledge.risk import assess
from guardian.remediation.candidates import (
    RegistryLike,
    generate_candidates,
    is_npm_finding,
    npm_purl,
)
from guardian.remediation.planner import make_plan
from guardian.storage.database import Database
from guardian.storage.remediation import SYSTEM_ACTOR

CASE_RULE = "dependency-vulnerabilities"
"""The fingerprint's vuln/rule part: one case covers every advisory of the package."""
REFRESHABLE = frozenset({CaseStatus.PROPOSED, CaseStatus.AWAITING_DECISION})
MAX_TITLE_IDS = 3


@dataclass(frozen=True)
class PackageGroup:
    name: str
    version: str | None
    findings: list[Finding]
    priority: Priority
    max_score: float

    @property
    def finding_ids(self) -> list[str]:
        return [f.id for f in self.findings]


def case_fingerprint(repo_root: str, package: str) -> str:
    return fingerprint_for(repo_root, npm_purl(package), CASE_RULE)


def group_npm_findings(
    findings: Sequence[Finding], assessments: dict[str, RiskAssessment]
) -> list[PackageGroup]:
    """Vulnerability findings of npm packages grouped per package name, best priority first."""
    by_package: dict[str, list[Finding]] = {}
    for finding in findings:
        if is_npm_finding(finding) and isinstance(finding.details, VulnerabilityDetails):
            by_package.setdefault(finding.details.package, []).append(finding)
    groups = []
    for name, items in by_package.items():
        scored = [assessments[f.id] for f in items if f.id in assessments]
        first = items[0].details
        groups.append(
            PackageGroup(
                name=name,
                version=first.version if isinstance(first, VulnerabilityDetails) else None,
                findings=sorted(items, key=lambda f: f.id),
                priority=min((a.priority for a in scored), default=Priority.P4),
                max_score=max((a.score or 0.0 for a in scored), default=0.0),
            )
        )
    return sorted(groups, key=lambda g: (g.priority.value, -g.max_score, g.name))


def _title(group: PackageGroup) -> str:
    ids = [
        f.details.vulnerability_id
        for f in group.findings
        if isinstance(f.details, VulnerabilityDetails)
    ]
    shown = ", ".join(sorted(ids)[:MAX_TITLE_IDS]) + (", ..." if len(ids) > MAX_TITLE_IDS else "")
    count = len(group.findings)
    noun = "vulnerability" if count == 1 else "vulnerabilities"
    version = f" {group.version}" if group.version else ""
    return f"{group.name}{version}: {count} known {noun} ({shown})"


def select_groups(
    groups: list[PackageGroup],
    *,
    min_priority: Priority,
    top: int,
    finding_ids: Sequence[str] | None,
) -> list[PackageGroup]:
    """Groups containing ``finding_ids`` (exact id or unique prefix), else the top N at or above
    ``min_priority``."""
    if finding_ids:
        wanted = [i.strip() for i in finding_ids if i.strip()]
        return [g for g in groups if any(f.startswith(w) for f in g.finding_ids for w in wanted)]
    eligible = [g for g in groups if g.priority.value <= min_priority.value]
    return eligible[: max(top, 0)]


def create_cases(  # noqa: PLR0913 - CLI switches map 1:1 onto keyword arguments
    db: Database,
    scan_id: str,
    *,
    settings: GuardianSettings,
    registry: RegistryLike | None,
    min_priority: Priority = Priority.P2,
    top: int = 5,
    finding_ids: Sequence[str] | None = None,
    no_ai: bool = False,
    chat_model: BaseChatModel | None = None,
) -> list[RemediationCase]:
    """Create or refresh one remediation case per selected vulnerable npm package."""
    record = db.scans.get(scan_id)
    profile = db.scans.profile(scan_id)
    sbom = db.sboms.load(scan_id)
    findings = db.findings.load(scan_id)
    code_index = db.code.load(scan_id)
    changes = db.findings.changes(scan_id)
    graph = DependencyGraph(build_knowledge_graph(profile, sbom, findings, changes))
    assessments = {a.finding_id: a for a in assess(findings, graph, code_index)}

    groups = select_groups(
        group_npm_findings(findings, assessments),
        min_priority=min_priority,
        top=top,
        finding_ids=finding_ids,
    )
    store = db.remediation
    repo_root = record.repository_root
    worktree_root = settings.data_dir / "worktrees"
    cases: list[RemediationCase] = []
    for group in groups:
        fingerprint = case_fingerprint(repo_root, group.name)
        existing = store.by_fingerprint(fingerprint)
        if existing is not None and existing.status not in REFRESHABLE:
            cases.append(existing)
            continue
        now = datetime.now(UTC)
        case = existing or RemediationCase(
            id=case_id_for(fingerprint),
            fingerprint=fingerprint,
            scan_id=scan_id,
            repository_root=repo_root,
            finding_ids=group.finding_ids,
            title=_title(group),
            priority=group.priority,
            created_at=now,
            updated_at=now,
        )
        if existing is None:
            store.create(case)
        else:
            # The case now tracks this scan: verification compares against it, and its
            # findings are the ones the candidates below target.
            case = store.refresh_case(case.id, scan_id, group.finding_ids)
        working = case
        candidates = generate_candidates(
            working,
            group.findings,
            sbom,
            graph,
            code_index,
            assessments,
            registry,
            Path(repo_root),
            worktree_root=worktree_root,
        )
        store.replace_candidates(case.id, candidates)
        db.audit.append(
            case.id,
            "candidates:generated",
            SYSTEM_ACTOR,
            {"scan_id": scan_id, "candidate_ids": [c.id for c in candidates]},
        )
        plan = make_plan(
            working,
            group.findings,
            assessments,
            candidates,
            settings=settings,
            no_ai=no_ai,
            chat_model=chat_model,
        )
        store.save_plan(plan)
        db.audit.append(case.id, "plan:created", SYSTEM_ACTOR, plan)
        if case.status is CaseStatus.PROPOSED:
            case = store.update_status(case.id, CaseStatus.AWAITING_DECISION)
        cases.append(case)
    return cases

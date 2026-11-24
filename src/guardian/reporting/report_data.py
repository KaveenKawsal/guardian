"""Assemble ReportData for a stored scan: findings prioritized by risk, with context.

Deterministic: every value comes from the stored scan (no network, no LLM).
"""

import re
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path

import guardian
from guardian.core.config import GuardianSettings
from guardian.core.models import (
    ChangeCategory,
    ChangeDetails,
    CodeDetails,
    CodeIndex,
    Component,
    DirectSource,
    Ecosystem,
    Finding,
    FindingKind,
    Priority,
    RepositoryProfile,
    RiskAssessment,
    RiskFactorName,
    Sbom,
    ScanRecord,
    Severity,
    VulnerabilityDetails,
)
from guardian.indexing.code_retriever import CodeRetriever, CodeSnippet
from guardian.knowledge.graph_builder import build_knowledge_graph
from guardian.knowledge.graph_queries import DependencyGraph
from guardian.knowledge.risk import (
    SEVERITY_WORDS,
    assess,
    language_families,
    package_family,
)
from guardian.reporting.models import (
    PackageRisk,
    PriorityCount,
    RemediationSection,
    ReportData,
    ReportFinding,
    ReportMeta,
    ReportSummary,
    SeverityCount,
)
from guardian.reporting.remediation_report import build_remediation_section
from guardian.storage.database import Database

MAX_PATHS = 3
MAX_SNIPPETS = 3
SNIPPET_BUDGET_LINES = 60
MAX_WARNINGS = 20
MAX_MESSAGE_CHARS = 300
_PRIORITY_ORDER = {p: i for i, p in enumerate(Priority)}
_OK_STATUSES = frozenset({"success", "skipped"})
_USAGE_PHRASES = {1.0: " that the code calls", 0.7: " that the code imports"}

_CHANGE_REMEDIATION = {
    ChangeCategory.CI_CONFIG: (
        "Review the CI configuration change for injected steps, new secret access or "
        "untrusted third-party actions."
    ),
    ChangeCategory.LOCKFILE_ONLY: (
        "Verify the lockfile change: it changed without a matching manifest change. "
        "Regenerate it from the manifest if the change was not intended."
    ),
    ChangeCategory.MANIFEST: (
        "Review the dependency change: confirm new or upgraded packages are intended, "
        "maintained and trusted."
    ),
    ChangeCategory.CONTAINER: (
        "Review the container configuration change (base image, privileges, exposed ports, "
        "secrets in build arguments)."
    ),
    ChangeCategory.SECURITY_CODE: (
        "Review the security-sensitive code change for regressions in authentication, "
        "authorization or cryptography."
    ),
    ChangeCategory.UNCOMMITTED: ("Review the uncommitted dependency change before committing it."),
}


def build_report(
    db: Database,
    scan_id: str,
    settings: GuardianSettings,
    *,
    max_findings: int = 500,
    include_code: bool = True,
) -> ReportData:
    """Load the scan (profile, SBOM, findings, changes, code index) and build the report.

    Raises ``guardian.storage.scans.ScanNotFoundError`` for unknown scans.
    """
    record = db.scans.get(scan_id)
    profile = db.scans.profile(scan_id)
    sbom = db.sboms.load(scan_id)
    findings = db.findings.load(scan_id)
    changes = db.findings.changes(scan_id)
    index = db.code.load(scan_id)

    graph = DependencyGraph(
        build_knowledge_graph(profile, sbom, findings, changes, code_index=index)
    )
    risks = assess(findings, graph, index)

    ranked = sorted(zip(findings, risks, strict=True), key=_sort_key)
    shown = ranked[: max(0, max_findings)]
    retriever = _retriever(profile, index) if include_code else None
    paths_cache: dict[str, list[list[str]]] = {}
    report_findings = [
        _report_finding(finding, risk, graph, retriever, paths_cache) for finding, risk in shown
    ]

    packages = _packages(findings, graph, index)
    limitations = _limitations(record, profile, sbom, index)
    if omitted := len(ranked) - len(shown):
        limitations.insert(
            0,
            f"{omitted} lower-priority finding(s) omitted from this report "
            f"(limit {max_findings}); all are counted in the summary.",
        )
    summary = _summary(ranked, packages, graph, sbom, index)
    remediation_section = build_remediation_section(
        db, scan_id, findings, {r.finding_id: r for r in risks}, settings
    )
    return ReportData(
        meta=ReportMeta(
            guardian_version=guardian.__version__,
            generated_at=datetime.now(UTC),
            repository=profile.name,
            source=_source(profile, settings),
            scan=record,
            ai_used=_ai_used(remediation_section),
        ),
        summary=summary,
        findings=report_findings,
        packages=packages,
        entry_points=list(index.entry_points) if index else [],
        tool_runs=list(record.tool_runs),
        limitations=limitations,
        remediation=remediation_section,
    )


def _ai_used(section: RemediationSection | None) -> bool:
    """True when the report carries AI inference (investigations or an LLM-chosen plan)."""
    if section is None:
        return False
    return any(
        c.investigations or (c.plan is not None and c.plan.decided_by == "llm")
        for c in section.cases
    )


def _sort_key(item: tuple[Finding, RiskAssessment]) -> tuple:
    finding, risk = item
    score = risk.score if risk.score is not None else -1.0
    return (
        _PRIORITY_ORDER[risk.priority],
        -score,
        -finding.severity.rank,
        finding.title,
        finding.id,
    )


def _retriever(profile: RepositoryProfile, index: CodeIndex | None) -> CodeRetriever | None:
    root = Path(profile.root)
    if index is None or not root.is_dir():
        return None
    return CodeRetriever(root, index)


def _report_finding(
    finding: Finding,
    risk: RiskAssessment,
    graph: DependencyGraph,
    retriever: CodeRetriever | None,
    paths_cache: dict[str, list[list[str]]],
) -> ReportFinding:
    paths: list[list[str]] = []
    if finding.kind is FindingKind.VULNERABILITY and finding.component_ref:
        ref = finding.component_ref
        if ref not in paths_cache:
            paths_cache[ref] = [
                [c.display_name for c in path]
                for path in graph.introduction_paths(ref, limit=MAX_PATHS)
            ]
        paths = paths_cache[ref]
    code: list[CodeSnippet] = []
    if retriever is not None:
        code = retriever.for_finding(
            finding, max_snippets=MAX_SNIPPETS, budget_lines=SNIPPET_BUDGET_LINES
        )
    return ReportFinding(
        finding=finding,
        risk=risk,
        code=code,
        introduction_paths=paths,
        remediation=remediation(finding, paths),
    )


# --- Remediation -----------------------------------------------------------------------


def remediation(finding: Finding, paths: list[list[str]]) -> str:
    """A concrete next step for a human reviewer."""
    details = finding.details
    if isinstance(details, VulnerabilityDetails):
        return _vulnerability_remediation(details, paths)
    if isinstance(details, CodeDetails):
        return _code_remediation(details)
    return _change_remediation(finding, details)


def _vulnerability_remediation(d: VulnerabilityDetails, paths: list[list[str]]) -> str:
    transitive = bool(paths) and len(paths[0]) > 1
    if d.recommended_fix:
        text = f"Upgrade {d.package} to {d.recommended_fix} or later."
    elif d.fixed_versions:
        text = f"Upgrade {d.package} to a fixed release ({', '.join(d.fixed_versions[:5])})."
    else:
        return (
            f"No fixed version of {d.package} is published: replace the package or isolate "
            "its use, and monitor the advisory for a fix."
        )
    if transitive:
        text += (
            f" It is a transitive dependency via {paths[0][0]}: upgrade {paths[0][0]} to a "
            f"release that depends on a fixed {d.package}, or pin/override {d.package}."
        )
    return text


def _code_remediation(d: CodeDetails) -> str:
    message = " ".join(d.message.split())
    if len(message) > MAX_MESSAGE_CHARS:
        message = message[: MAX_MESSAGE_CHARS - 3].rstrip() + "..."
    weakness = f" ({', '.join(d.cwe_ids[:3])})" if d.cwe_ids else ""
    return f"Fix the pattern flagged by {d.rule_id}{weakness}: {message}"


def _change_remediation(finding: Finding, d: ChangeDetails) -> str:
    if d.category is ChangeCategory.SENSITIVE_FILE:
        files = ", ".join(d.paths[:3]) or "the file"
        if "still present" in finding.title.lower():
            return (
                f"Remove {files} from the repository, rotate any secrets it contains, and "
                "purge it from git history (e.g. git filter-repo)."
            )
        return (
            f"Rotate any secrets {files} contained: it was removed but remains in git history "
            "until purged."
        )
    return _CHANGE_REMEDIATION.get(d.category, "Review the change.")


# --- Packages --------------------------------------------------------------------------


def _packages(
    findings: list[Finding], graph: DependencyGraph, index: CodeIndex | None
) -> list[PackageRisk]:
    groups: dict[str, list[tuple[Finding, VulnerabilityDetails]]] = defaultdict(list)
    for finding in findings:
        if isinstance(finding.details, VulnerabilityDetails):
            d = finding.details
            key = finding.component_ref or f"{d.package}@{d.version}"
            groups[key].append((finding, d))
    if not groups:
        return []
    depths = graph.depths()
    components = {c.ref: c for c in graph.components()}
    families = language_families(index)
    packages = []
    for key, items in groups.items():
        first = items[0][1]
        component: Component | None = components.get(key)
        depth = depths.get(key)
        used = (
            graph.is_imported(key)
            if component is not None and package_family(component, first.ecosystem) in families
            else None
        )
        fixes = [d.recommended_fix for _, d in items if d.recommended_fix]
        packages.append(
            PackageRisk(
                package=_component_name(component) if component else first.package,
                version=component.version if component else first.version,
                ecosystem=first.ecosystem,
                direct=(depth == 1) if depth is not None else None,
                used_in_code=used,
                vulnerability_count=len(items),
                worst_severity=max((f.severity for f, _ in items), key=lambda s: s.rank),
                recommended_fix=max(fixes, key=_version_key) if fixes else None,
            )
        )
    return sorted(
        packages,
        key=lambda p: (
            -p.worst_severity.rank,
            p.used_in_code is not True,
            p.direct is not True,
            -p.vulnerability_count,
            p.package.lower(),
        ),
    )


def _component_name(component: Component) -> str:
    return f"{component.group}/{component.name}" if component.group else component.name


def _version_key(version: str) -> tuple:
    """Natural ordering good enough to pick the highest of several fixed versions."""
    parts = re.findall(r"\d+|[A-Za-z]+", version)
    return tuple((0, int(p), "") if p.isdigit() else (-1, 0, p) for p in parts)


# --- Summary ---------------------------------------------------------------------------


def _summary(
    ranked: list[tuple[Finding, RiskAssessment]],
    packages: list[PackageRisk],
    graph: DependencyGraph,
    sbom: Sbom | None,
    index: CodeIndex | None,
) -> ReportSummary:
    severities = Counter(f.severity for f, _ in ranked)
    priorities = Counter(r.priority for _, r in ranked)
    kinds = Counter(f.kind for f, _ in ranked)
    return ReportSummary(
        headline=_headline(ranked, priorities),
        total_findings=len(ranked),
        by_severity=[SeverityCount(severity=s, count=severities[s]) for s in Severity],
        by_priority=[PriorityCount(priority=p, count=priorities[p]) for p in Priority],
        by_kind={k.value: kinds[k] for k in FindingKind},
        components=len(sbom.components) if sbom else 0,
        direct_dependencies=len(graph.direct_dependencies()),
        vulnerable_packages=len(packages),
        vulnerable_packages_used_in_code=sum(p.used_in_code is True for p in packages),
        files_indexed=len(index.files) if index else 0,
        entry_points=len(index.entry_points) if index else 0,
    )


def _headline(ranked: list[tuple[Finding, RiskAssessment]], priorities: Counter) -> str:
    if not ranked:
        return "No security findings were reported for this scan."
    top_finding, top_risk = ranked[0]
    if top_risk.priority is Priority.P1:
        count = priorities[Priority.P1]
        verb = "needs" if count == 1 else "need"
        noun = "finding" if count == 1 else "findings"
        lead = "" if count == 1 else "including "
        return f"{count} {noun} {verb} action now (P1), {lead}{_describe(top_finding, top_risk)}."
    if top_risk.priority is Priority.P2:
        count = priorities[Priority.P2]
        return (
            f"No findings need immediate action; {count} should be scheduled soon (P2), "
            f"led by {_describe(top_finding, top_risk)}."
        )
    return f"No findings need prompt action; {len(ranked)} are backlog or informational (P3/P4)."


def _describe(finding: Finding, risk: RiskAssessment) -> str:
    """Short noun phrase, e.g. 'a critical vulnerability in jsonwebtoken'."""
    severity = SEVERITY_WORDS[finding.severity].lower()
    article = "an" if severity[0] in "aeiou" else "a"
    details = finding.details
    if isinstance(details, VulnerabilityDetails):
        reach = next((f.value for f in risk.factors if f.name is RiskFactorName.REACHABILITY), None)
        usage = _USAGE_PHRASES.get(reach, "") if reach is not None else ""
        return f"{article} {severity} vulnerability in {details.package}{usage}"
    if isinstance(details, CodeDetails):
        where = f" in {finding.path}" if finding.path else ""
        return f"{article} {severity} code finding ({details.rule_id.rsplit('.', 1)[-1]}){where}"
    return f"{article} {severity} repository change ({details.category.value})"


# --- Limitations and meta --------------------------------------------------------------


def _limitations(
    record: ScanRecord, profile: RepositoryProfile, sbom: Sbom | None, index: CodeIndex | None
) -> list[str]:
    notes = [
        f"{run.tool} {run.status}" + (f": {run.error}" if run.error else "")
        for run in record.tool_runs
        if run.status not in _OK_STATUSES
    ]
    notes += [f"Scan warning: {w}" for w in record.warnings[:MAX_WARNINGS]]
    if len(record.warnings) > MAX_WARNINGS:
        notes.append(f"... and {len(record.warnings) - MAX_WARNINGS} more scan warning(s).")
    notes.append(
        "Exploitability was not assessed (AI investigation not run); risk scores are a "
        "deterministic Guardian heuristic over severity, exposure, reachability and fix."
    )
    if sbom is None:
        notes.append("No SBOM was stored: dependency depth and package context are unavailable.")
    elif sbom.direct_source is DirectSource.GRAPH_INFERENCE:
        notes.append(
            "Direct dependencies were inferred from the dependency graph (no manifest or SBOM "
            "root link); packages that are also transitive may be misclassified."
        )
    if index is None:
        notes.append("No code index: reachability, entry points and code context are unavailable.")
    elif index.skipped_files:
        skipped = ", ".join(f"{reason} {n}" for reason, n in sorted(index.skipped_files.items()))
        total = sum(index.skipped_files.values())
        notes.append(f"Source indexing skipped {total} file(s) ({skipped}).")
    for ecosystem in profile.ecosystems:
        if (
            ecosystem.ecosystem is not Ecosystem.CONTAINER
            and ecosystem.manifests
            and not ecosystem.lockfiles
        ):
            notes.append(
                f"No lockfile found for {ecosystem.ecosystem.value}: resolved versions and "
                "transitive dependencies may be incomplete."
            )
    return notes


def _source(profile: RepositoryProfile, settings: GuardianSettings) -> str:
    root = Path(profile.root)
    workspaces = settings.data_dir / "workspaces"
    try:
        remote = root.resolve().is_relative_to(workspaces.resolve())
    except OSError:
        remote = False
    return f"remote clone of {profile.name}" if remote else profile.root

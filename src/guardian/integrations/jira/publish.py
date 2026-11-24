"""Publish remediation cases as Jira issues: one issue per case, idempotent.

A case that already has a ``jira_links`` row updates its issue. Otherwise Guardian searches for
the case's fingerprint label first, so an issue is found again even if the local database lost
the link (e.g. a fresh ``~/.guardian``), and only then creates a new one.

Everything that comes from the scanned repository or an advisory goes into the description as
ADF text nodes, never as markup.
"""

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from guardian.core.config import GuardianSettings
from guardian.core.models import (
    Finding,
    FindingKind,
    Priority,
    RiskAssessment,
    VulnerabilityDetails,
)
from guardian.core.remediation_models import (
    CaseStatus,
    JiraLink,
    RemediationCandidate,
    RemediationCase,
    RemediationPlan,
    jira_label_for,
)
from guardian.integrations.jira import adf
from guardian.integrations.jira.client import JiraClient, JiraError
from guardian.integrations.jira.commands import GRAMMAR_HELP
from guardian.knowledge.graph_builder import build_knowledge_graph
from guardian.knowledge.graph_queries import DependencyGraph
from guardian.knowledge.risk import assess
from guardian.storage.database import Database
from guardian.storage.remediation import SYSTEM_ACTOR

MAX_SUMMARY_CHARS = 255
MAX_EVIDENCE_ITEMS = 20
MAX_PATHS = 3
MAX_FINDINGS_SHOWN = 5
HTTP_BAD_REQUEST = 400

JIRA_PRIORITY: dict[Priority, str] = {
    Priority.P1: "Highest",
    Priority.P2: "High",
    Priority.P3: "Medium",
    Priority.P4: "Low",
}
_LABEL_UNSAFE_RE = re.compile(r"[^a-z0-9_.-]+")
_UNPUBLISHABLE = frozenset({CaseStatus.CLOSED, CaseStatus.DECLINED})


@dataclass(frozen=True, slots=True)
class CaseContext:
    """What a Jira issue describes, loaded by the caller (no scanning happens here)."""

    findings: Sequence[Finding]
    assessments: Sequence[RiskAssessment]
    candidates: Sequence[RemediationCandidate]
    plan: RemediationPlan | None
    dependency_paths: Mapping[str, Sequence[Sequence[str]]] = field(default_factory=dict)
    """finding id -> introduction paths (component display names), when known."""


@dataclass(slots=True)
class PublishReport:
    links: list[JiraLink] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    """Case ids below the priority threshold, past the cap, or already closed."""
    errors: list[tuple[str, str]] = field(default_factory=list)
    """(case id, one-line error)."""


# --- context ------------------------------------------------------------------------------


def load_case_contexts(
    db: Database, scan_id: str, case_ids: Sequence[str] | None = None
) -> dict[str, CaseContext]:
    """Case id -> what its issue describes, loaded from the stored scan (no rescanning).

    ``case_ids`` limits the result to those cases (all of the scan's cases when None).
    """
    profile = db.scans.profile(scan_id)
    sbom = db.sboms.load(scan_id)
    findings = db.findings.load(scan_id)
    index = db.code.load(scan_id)
    graph = DependencyGraph(
        build_knowledge_graph(
            profile, sbom, findings, db.findings.changes(scan_id), code_index=index
        )
    )
    assessments = assess(findings, graph, index)
    paths: dict[str, list[list[str]]] = {}
    for finding in findings:
        if finding.kind is FindingKind.VULNERABILITY and finding.component_ref:
            paths[finding.id] = [
                [c.display_name for c in path]
                for path in graph.introduction_paths(finding.component_ref, limit=MAX_PATHS)
            ]
    wanted_cases = None if case_ids is None else set(case_ids)
    contexts: dict[str, CaseContext] = {}
    for case in db.remediation.list():
        if case.scan_id != scan_id or (wanted_cases is not None and case.id not in wanted_cases):
            continue
        wanted = set(case.finding_ids)
        contexts[case.id] = CaseContext(
            findings=[f for f in findings if f.id in wanted],
            assessments=[a for a in assessments if a.finding_id in wanted],
            candidates=db.remediation.candidates(case.id),
            plan=db.remediation.plan(case.id),
            dependency_paths={k: v for k, v in paths.items() if k in wanted},
        )
    return contexts


# --- selection ----------------------------------------------------------------------------


def select_for_publishing(
    cases: Sequence[RemediationCase], settings: GuardianSettings
) -> list[RemediationCase]:
    """Open cases at or above ``jira_min_priority``, most urgent first, capped at
    ``jira_max_issues`` (P1 sorts before P2; ties by creation time, then id)."""
    eligible = [
        c
        for c in cases
        if c.status not in _UNPUBLISHABLE and c.priority.value <= settings.jira_min_priority.value
    ]
    eligible.sort(key=lambda c: (c.priority.value, c.created_at, c.id))
    return eligible[: settings.jira_max_issues]


def publish_cases(
    db: Database,
    jira: JiraClient,
    settings: GuardianSettings,
    cases: Sequence[RemediationCase],
    load_context: Callable[[RemediationCase], CaseContext],
) -> PublishReport:
    report = PublishReport()
    selected = select_for_publishing(cases, settings)
    chosen = {c.id for c in selected}
    report.skipped = [c.id for c in cases if c.id not in chosen]
    for case in selected:
        context = load_context(case)
        try:
            link = publish_case(
                db,
                jira,
                settings,
                case,
                findings=context.findings,
                assessments=context.assessments,
                candidates=context.candidates,
                plan=context.plan,
                dependency_paths=context.dependency_paths,
            )
        except JiraError as exc:
            report.errors.append((case.id, str(exc)))
            continue
        report.links.append(link)
    return report


# --- one case -----------------------------------------------------------------------------


def publish_case(  # noqa: PLR0913 - the case plus everything its issue describes
    db: Database,
    jira: JiraClient,
    settings: GuardianSettings,
    case: RemediationCase,
    *,
    findings: Sequence[Finding],
    assessments: Sequence[RiskAssessment],
    candidates: Sequence[RemediationCandidate],
    plan: RemediationPlan | None,
    dependency_paths: Mapping[str, Sequence[Sequence[str]]] | None = None,
    actor: str = SYSTEM_ACTOR,
) -> JiraLink:
    """Create or update the case's issue, link it, audit it, and mark the case as awaiting
    a decision (``PROPOSED -> AWAITING_DECISION``)."""
    if not settings.jira_project_key:
        msg = "JIRA_PROJECT_KEY is not set"
        raise JiraError(msg)
    case_findings = _case_findings(case, findings)
    chosen, alternatives = _chosen_and_alternatives(candidates, plan)
    fields: dict[str, Any] = {
        "summary": issue_summary(case, case_findings),
        "description": issue_description(
            case,
            case_findings,
            assessments,
            candidates,
            plan,
            dependency_paths or {},
        ),
        "labels": issue_labels(case, case_findings, chosen),
        "priority": {"name": JIRA_PRIORITY[case.priority]},
    }
    payload = {
        "fingerprint": case.fingerprint,
        "summary": fields["summary"],
        "chosen_candidate_id": chosen.id if chosen else None,
        "alternatives": [c.id for c in alternatives],
    }

    link = db.remediation.jira_link(case.id)
    if link is not None:
        _update(jira, link.issue_key, fields)
        db.audit.append(case.id, "jira:updated", actor, payload | {"issue_key": link.issue_key})
    else:
        key = _find_by_label(jira, settings.jira_project_key, jira_label_for(case.fingerprint))
        if key is not None:
            _update(jira, key, fields)
            event = "jira:updated"
        else:
            create = fields | {
                "project": {"key": settings.jira_project_key},
                "issuetype": {"name": settings.jira_issue_type},
            }
            key = _create(jira, create)
            event = "jira:published"
        link = db.remediation.link_jira(case.id, key, actor)
        db.audit.append(case.id, event, actor, payload | {"issue_key": key})

    if db.remediation.get(case.id).status is CaseStatus.PROPOSED:
        db.remediation.update_status(
            case.id,
            CaseStatus.AWAITING_DECISION,
            actor=actor,
            payload={"issue_key": link.issue_key},
        )
    return db.remediation.jira_link(case.id) or link


def _create(jira: JiraClient, fields: dict[str, Any]) -> str:
    try:
        return jira.create_issue(fields)
    except JiraError as exc:
        if not _priority_rejected(exc):
            raise
        # Some projects hide the priority field on their screens; publish without it.
        return jira.create_issue({k: v for k, v in fields.items() if k != "priority"})


def _update(jira: JiraClient, key: str, fields: dict[str, Any]) -> None:
    try:
        jira.update_issue(key, fields)
    except JiraError as exc:
        if not _priority_rejected(exc):
            raise
        jira.update_issue(key, {k: v for k, v in fields.items() if k != "priority"})


def _priority_rejected(exc: JiraError) -> bool:
    return exc.status_code == HTTP_BAD_REQUEST and "priority" in exc.field_errors


def _find_by_label(jira: JiraClient, project_key: str, label: str) -> str | None:
    jql = f'project = "{_jql_escape(project_key)}" AND labels = "{_jql_escape(label)}"'
    for issue in jira.iter_search(jql, ["key"], max_pages=1):
        key = issue.get("key")
        if isinstance(key, str):
            return key
    return None


def _jql_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


# --- issue content ------------------------------------------------------------------------


def _case_findings(case: RemediationCase, findings: Sequence[Finding]) -> list[Finding]:
    by_id = {f.id: f for f in findings}
    ordered = [by_id[i] for i in case.finding_ids if i in by_id]
    return ordered or [f for f in findings if f.id in case.finding_ids]


def _chosen_and_alternatives(
    candidates: Sequence[RemediationCandidate], plan: RemediationPlan | None
) -> tuple[RemediationCandidate | None, list[RemediationCandidate]]:
    by_id = {c.id: c for c in candidates}
    if plan is None:
        return None, list(candidates)
    chosen = by_id.get(plan.chosen_candidate_id)
    alternatives = [
        by_id[i] for i in plan.alternatives if i in by_id and i != plan.chosen_candidate_id
    ]
    return chosen, alternatives


def _cve(details: VulnerabilityDetails) -> str:
    ids = [details.vulnerability_id, *details.aliases]
    return next((i for i in ids if i.upper().startswith("CVE-")), details.vulnerability_id)


def _one_line(value: str) -> str:
    return adf.clean_text(" ".join(value.split()), MAX_SUMMARY_CHARS)


def issue_summary(case: RemediationCase, findings: Sequence[Finding]) -> str:
    """``[Guardian][HIGH] jsonwebtoken 0.4.0 — <advisory title> (CVE-…)``, at most 255 chars."""
    head = f"[Guardian][{case.priority.label.upper()}] "
    suffix = ""
    primary = findings[0] if findings else None
    if primary is not None and isinstance(primary.details, VulnerabilityDetails):
        details = primary.details
        component = _one_line(" ".join(p for p in (details.package, details.version) if p))
        head += f"{component} \u2014 "
        title = _one_line(details.summary or primary.title)
        suffix = f" ({_one_line(_cve(details))})"
        if len(findings) > 1:
            suffix += f" +{len(findings) - 1} more"
    else:
        title = _one_line(primary.title if primary is not None else case.title)
    room = MAX_SUMMARY_CHARS - len(head) - len(suffix)
    if room < 4:  # noqa: PLR2004 - no space left for "x..."
        return (head + title + suffix)[:MAX_SUMMARY_CHARS]
    if len(title) > room:
        title = title[: room - 3] + "..."
    return head + title + suffix


def _label(value: str) -> str:
    return _LABEL_UNSAFE_RE.sub("-", value.lower()).strip("-")[:255]


def _ecosystem(findings: Sequence[Finding], chosen: RemediationCandidate | None) -> str | None:
    for finding in findings:
        if isinstance(finding.details, VulnerabilityDetails) and finding.details.ecosystem:
            return finding.details.ecosystem
    if chosen is not None and chosen.component.startswith("pkg:"):
        return chosen.component[4:].split("/", 1)[0]
    return None


def issue_labels(
    case: RemediationCase, findings: Sequence[Finding], chosen: RemediationCandidate | None
) -> list[str]:
    labels = ["guardian", jira_label_for(case.fingerprint)]
    if (ecosystem := _ecosystem(findings, chosen)) and (label := _label(ecosystem)):
        labels.append(label)
    if chosen is not None:
        labels.append(chosen.action_type.value.lower())
    return list(dict.fromkeys(labels))


def issue_description(  # noqa: PLR0913, PLR0917 - one argument per described part
    case: RemediationCase,
    findings: Sequence[Finding],
    assessments: Sequence[RiskAssessment],
    candidates: Sequence[RemediationCandidate],
    plan: RemediationPlan | None,
    dependency_paths: Mapping[str, Sequence[Sequence[str]]],
) -> adf.Node:
    chosen, alternatives = _chosen_and_alternatives(candidates, plan)
    risk_by_finding = {a.finding_id: a for a in assessments}
    shown = list(findings)[:MAX_FINDINGS_SHOWN]
    blocks: list[adf.Node | None] = [
        adf.paragraph(
            "Guardian remediation case ",
            adf.code(case.id),
            " (scan ",
            adf.code(case.scan_id[:12]),
            "). Facts marked ",
            adf.tag("verified"),
            " come from deterministic tools; ",
            adf.tag("unknown"),
            " means no evidence either way.",
        ),
        adf.heading("Risk"),
    ]
    for finding in shown:
        blocks.extend(_risk_blocks(finding, risk_by_finding.get(finding.id)))
    blocks.append(adf.heading("Affected component"))
    for finding in shown:
        blocks.extend(_component_blocks(finding, dependency_paths.get(finding.id, ())))
    blocks.append(adf.heading("Evidence"))
    blocks.append(_evidence_list(shown) or adf.paragraph("No evidence records."))
    blocks.extend(_action_blocks(chosen, alternatives, plan))
    blocks.extend(
        [
            adf.heading("How to decide"),
            adf.paragraph(
                "Comment on this issue with exactly one command on the first line "
                "(only allowlisted approvers are accepted):"
            ),
            adf.code_block(GRAMMAR_HELP),
        ]
    )
    return adf.doc(*blocks)


def _risk_blocks(finding: Finding, risk: RiskAssessment | None) -> list[adf.Node]:
    blocks = [adf.paragraph(adf.strong(finding.title), " ", adf.code(finding.id[:16]))]
    if risk is None:
        blocks.append(adf.paragraph("No risk assessment available ", adf.tag("unknown")))
        return blocks
    score = f"{risk.score:.1f}" if risk.score is not None else "unknown"
    blocks.append(
        adf.paragraph(
            adf.strong("Score: "),
            f"{score} / 100 · priority {risk.priority.value} ({risk.priority.label}) · "
            f"confidence {risk.confidence.value} · known weight {risk.known_weight:.2f}",
        )
    )
    rows = [
        [
            factor.name.value,
            f"{factor.weight:.2f}",
            f"{factor.value:.2f}" if factor.value is not None else "unknown",
            adf.tag("verified" if factor.value is not None else "unknown"),
            factor.rationale,
        ]
        for factor in risk.factors
    ]
    blocks.append(adf.table(["Factor", "Weight", "Value", "Source", "Rationale"], rows))
    blocks.append(adf.paragraph(risk.summary))
    return blocks


def _component_blocks(finding: Finding, paths: Sequence[Sequence[str]]) -> list[adf.Node]:
    details = finding.details
    if isinstance(details, VulnerabilityDetails):
        parts: list[adf.Inline] = [adf.code(f"{details.package}@{details.version or '?'}")]
        if details.purl:
            parts += [" ", adf.code(details.purl)]
        if details.ecosystem:
            parts.append(f" ({details.ecosystem})")
        blocks = [adf.labelled("Component", *parts)]
        if details.fixed_versions:
            blocks.append(
                adf.labelled(
                    "Fixed in", ", ".join(details.fixed_versions[:10]), " ", adf.tag("verified")
                )
            )
    else:
        location = finding.location or finding.component_ref or "-"
        blocks = [adf.labelled("Location", adf.code(location))]
    if paths:
        items = [" → ".join(path) for path in list(paths)[:MAX_PATHS]]
        blocks.append(adf.labelled("Dependency path", adf.tag("verified")))
        if (path_list := adf.bullet_list(items)) is not None:
            blocks.append(path_list)
    return blocks


def _evidence_list(findings: Sequence[Finding]) -> adf.Node | None:
    items: list[list[adf.Inline]] = []
    for finding in findings:
        for ev in finding.evidence:
            item: list[adf.Inline] = [adf.tag(ev.kind.value), " ", ev.summary]
            where = f"{ev.path}:{ev.line}" if ev.path and ev.line else ev.path
            if where:
                item += [" ", adf.code(where)]
            if ev.commit:
                item += [" commit ", adf.code(ev.commit[:12])]
            if ev.url:
                item += [" ", adf.code(ev.url)]
            items.append(item)
            if len(items) >= MAX_EVIDENCE_ITEMS:
                return adf.bullet_list(items)
    return adf.bullet_list(items)


def _candidate_line(candidate: RemediationCandidate) -> list[adf.Inline]:
    target = candidate.component
    if candidate.from_version or candidate.to_version:
        target += f" {candidate.from_version or '?'} → {candidate.to_version or '-'}"
    line: list[adf.Inline] = [
        adf.strong(candidate.action_type.value),
        " ",
        adf.code(target),
        f" · semver {candidate.semver_jump.value}",
    ]
    if candidate.expected_risk_reduction is not None:
        line.append(f" · expected risk reduction {candidate.expected_risk_reduction:.1f} points")
    if candidate.version_verified is False:
        line += [" ", adf.tag("unverified version")]
    line += [" · id ", adf.code(candidate.id)]
    return line


def _action_blocks(
    chosen: RemediationCandidate | None,
    alternatives: Sequence[RemediationCandidate],
    plan: RemediationPlan | None,
) -> list[adf.Node | None]:
    blocks: list[adf.Node | None] = [adf.heading("Recommended action")]
    if chosen is None:
        blocks.append(adf.paragraph("No remediation plan recorded yet."))
    else:
        blocks.append(adf.paragraph(*_candidate_line(chosen)))
    if alternatives:
        blocks.append(adf.heading("Alternatives", 3))
        blocks.append(adf.bullet_list([_candidate_line(c) for c in alternatives]))
    if chosen is not None:
        blocks.append(adf.heading("Compatibility notes", 3))
        notes = adf.bullet_list([[adf.tag("verified"), " ", n] for n in chosen.compatibility_notes])
        blocks.append(notes or adf.paragraph("No known compatibility notes."))
        blocks.append(adf.heading("Rollback", 3))
        blocks.append(adf.code_block(chosen.rollback))
    if plan is not None:
        if plan.source == "inferred":
            model = "/".join(p for p in (plan.llm_provider, plan.llm_model) if p) or "LLM"
            blocks.append(adf.heading("Guardian's assessment (AI inference)", 3))
            blocks.append(
                adf.paragraph(
                    adf.tag("inferred"),
                    f" Produced by {model}; it chose among the candidates above and does not "
                    f"establish facts. Confidence: {plan.confidence.value}.",
                )
            )
        else:
            blocks.append(adf.heading("Selection rationale (deterministic)", 3))
        blocks.append(adf.paragraph(plan.rationale))
    return blocks

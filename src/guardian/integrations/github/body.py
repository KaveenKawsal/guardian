"""Title and markdown body of the pull request Guardian opens after a VERIFIED fix.

Every value that comes from the scanned repository, an advisory, a Jira user or an LLM is
untrusted: inline values go into code spans and free text into fenced ``text`` blocks, both with
a fence longer than any backtick run inside. That keeps markdown, HTML, links and ``@mentions``
inert. AI output appears only in a section labelled as inference.
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass, field

from guardian.core.models import Finding
from guardian.core.remediation_models import (
    DecisionType,
    HumanDecision,
    RemediationCandidate,
    RemediationCase,
    RemediationPlan,
    ValidationRun,
    VerificationResult,
)
from guardian.storage.database import Database
from guardian.storage.findings import FindingNotFoundError

MAX_BODY_CHARS = 60_000  # GitHub's limit is 65,536
MAX_INLINE_CHARS = 200
MAX_BLOCK_CHARS = 4_000
MAX_LIST_ITEMS = 25
MAX_TITLE_CHARS = 200
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_BACKTICKS_RE = re.compile(r"`+")


def _clean(value: object, limit: int) -> str:
    text = _CONTROL_RE.sub("", str(value))
    return text if len(text) <= limit else text[: limit - 3] + "..."


def inline(value: object) -> str:
    """``value`` as a markdown code span (single line)."""
    text = " ".join(_clean(value, MAX_INLINE_CHARS).split()) or "-"
    longest = max((len(m) for m in _BACKTICKS_RE.findall(text)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def fenced(value: object) -> str:
    """``value`` as a fenced ``text`` block (multi-line)."""
    text = _clean(value, MAX_BLOCK_CHARS).replace("\r", "")
    longest = max((len(m) for m in _BACKTICKS_RE.findall(text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}text\n{text}\n{fence}"


@dataclass(frozen=True)
class PrContext:
    case: RemediationCase
    branch: str
    commit_sha: str
    candidate: RemediationCandidate | None
    decision: HumanDecision | None
    revalidated_by: HumanDecision | None
    jira_key: str | None
    validation: ValidationRun | None
    verification: VerificationResult
    advisories: list[tuple[str, str]] = field(default_factory=list)
    """(finding id, advisory id or title)"""
    plan: RemediationPlan | None = None


def _advisory(finding: Finding) -> str:
    details = finding.details
    vuln_id = getattr(details, "vulnerability_id", None)
    aliases = [a for a in getattr(details, "aliases", None) or [] if a != vuln_id][:3]
    if vuln_id:
        return vuln_id + (f" ({', '.join(aliases)})" if aliases else "")
    return finding.title


def _approval(
    decisions: Sequence[HumanDecision],
) -> tuple[HumanDecision | None, HumanDecision | None]:
    approved = [d for d in decisions if d.decision in {DecisionType.ACCEPT, DecisionType.MODIFY}]
    if not approved:
        return None, None
    last = approved[-1]
    later = [
        d
        for d in decisions
        if d.decision is DecisionType.REVALIDATE and d.decided_at >= last.decided_at
    ]
    return last, (later[-1] if later else None)


def load_pr_context(db: Database, case_id: str, applied: dict, verification: dict) -> PrContext:
    case = db.remediation.get(case_id)
    candidates = {c.id: c for c in db.remediation.candidates(case_id)}
    plan = db.remediation.plan(case_id)
    candidate_id = applied.get("candidate_id") or (plan.chosen_candidate_id if plan else None)
    decision, revalidated = _approval(db.remediation.decisions(case_id))
    validations = db.remediation.validations(case_id)
    link = db.remediation.jira_link(case_id)
    advisories: list[tuple[str, str]] = []
    for finding_id in case.finding_ids[:MAX_LIST_ITEMS]:
        try:
            advisories.append((finding_id, _advisory(db.findings.get(case.scan_id, finding_id))))
        except FindingNotFoundError:
            advisories.append((finding_id, finding_id))
    return PrContext(
        case=case,
        branch=str(applied.get("branch") or ""),
        commit_sha=str(applied.get("commit_sha") or ""),
        candidate=candidates.get(candidate_id) if candidate_id else None,
        decision=decision,
        revalidated_by=revalidated,
        jira_key=case.jira_key or (link.issue_key if link else None),
        validation=validations[-1] if validations else None,
        verification=VerificationResult.model_validate(verification),
        advisories=advisories,
        plan=plan,
    )


def pr_title(ctx: PrContext) -> str:
    candidate = ctx.candidate
    if candidate is not None:
        target = f" to {candidate.to_version}" if candidate.to_version else ""
        package = candidate.component.removeprefix("pkg:npm/")
        text = f"guardian: {candidate.action_type.value.lower()} {package}{target}"
    else:
        text = f"guardian: {ctx.case.title}"
    text = " ".join(_clean(text, MAX_TITLE_CHARS).split())
    return f"{text} ({ctx.case.id})"


def _risk(value: float | None) -> str:
    return "unknown" if value is None else f"{value:.1f}"


def _decision_lines(ctx: PrContext) -> list[str]:
    d = ctx.decision
    if d is None:
        return ["- No ACCEPT/MODIFY decision found (this should not happen)."]
    lines = [
        (
            f"- **{d.decision.value}** by {inline(d.actor_display)} ({inline(d.actor_id)}) "
            f"via {inline(d.channel)} at {inline(d.decided_at.isoformat())}"
        ),
    ]
    if d.modify is not None:
        changes = d.modify.model_dump(exclude_none=True)
        lines.append("- Modification: " + ", ".join(f"{k}={inline(v)}" for k, v in changes.items()))
    if ctx.jira_key:
        lines.append(f"- Jira: {inline(ctx.jira_key)}")
    if d.jira_comment_id:
        lines.append(f"- Jira comment: {inline(d.jira_comment_id)}")
    if ctx.revalidated_by is not None:
        r = ctx.revalidated_by
        lines.append(
            f"- Re-validated by {inline(r.actor_display)} via {inline(r.channel)} at "
            f"{inline(r.decided_at.isoformat())}"
        )
    return lines


def _candidate_lines(ctx: PrContext) -> list[str]:
    c = ctx.candidate
    if c is None:
        return ["- Change made from a human-provided branch/commit (no Guardian candidate)."]
    lines = [
        (
            f"- Candidate {inline(c.id)}: {inline(c.action_type.value)} {inline(c.component)} "
            f"{inline(c.from_version or '?')} → {inline(c.to_version or '-')}"
        ),
        (
            f"- Semver jump: {inline(c.semver_jump.value)}; version verified in the registry: "
            f"{inline(c.version_verified)}"
        ),
    ]
    if c.manifest_path:
        lines.append(f"- Manifest: {inline(c.manifest_path)}")
    lines += [f"- Compatibility: {inline(n)}" for n in c.compatibility_notes[:MAX_LIST_ITEMS]]
    lines.append(f"- Rollback: {inline(c.rollback)}")
    return lines


def _validation_lines(ctx: PrContext) -> list[str]:
    run = ctx.validation
    if run is None:
        return ["- No validation run recorded."]
    lines = [f"- Sandbox: {inline(run.sandbox)}; commit {inline((run.commit_sha or '-')[:12])}"]
    if run.tests_discovered:
        lines.append(
            f"- Tests: {run.tests_passed or 0}/{run.tests_discovered} passed, "
            f"{run.tests_failed or 0} failed"
        )
    lines += ["", "| Step | Status | Exit | Duration | Note |", "|---|---|---|---|---|"]
    for step in run.steps:
        note = "known conflict: intentional challenge code" if step.known_conflict else ""
        if step.detail:
            note = f"{note}; {step.detail}" if note else step.detail
        exit_code = "-" if step.exit_code is None else str(step.exit_code)
        lines.append(
            f"| {step.name} | {inline(step.status.value)} | {exit_code} | "
            f"{step.duration_seconds:.1f}s | {inline(note) if note else ''} |"
        )
    return lines


def _verification_lines(ctx: PrContext) -> list[str]:
    v = ctx.verification
    diff = v.sbom_diff
    lines = [
        f"- Verdict: **{v.status.value}** (confidence {inline(v.confidence.value)})",
        f"- Risk score: {_risk(v.risk_before)} → {_risk(v.risk_after)}",
        (
            f"- Findings resolved: {len(v.target_findings_resolved)}; still present: "
            f"{len(v.findings_still_present)}; new: {len(v.new_findings)}"
        ),
        (
            f"- SBOM: +{len(diff.added)} added, -{len(diff.removed)} removed, "
            f"~{len(diff.changed)} changed"
        ),
    ]
    lines += [
        f"  - {inline(ch.purl_base)} {inline(ch.from_version or '?')} → "
        f"{inline(ch.to_version or '?')}"
        for ch in diff.changed[:MAX_LIST_ITEMS]
    ]
    if v.reasons:
        lines += ["", "Reasons:", "", fenced("\n".join(v.reasons[:MAX_LIST_ITEMS]))]
    return lines


def _ai_lines(ctx: PrContext) -> list[str]:
    plan = ctx.plan
    if plan is None or plan.source != "inferred":
        return []
    model = " / ".join(m for m in (plan.llm_provider, plan.llm_model) if m) or "an LLM"
    return [
        "",
        "### AI assessment (inference, not verified)",
        "",
        (
            f"Chosen by {inline(model)} from Guardian's deterministic candidates, confidence "
            f"{inline(plan.confidence)}. This explains the choice; the facts above are what "
            "Guardian verified."
        ),
        "",
        fenced(plan.rationale),
    ]


def pr_body(ctx: PrContext) -> str:
    case = ctx.case
    findings = [
        f"- {inline(advisory)} (finding {inline(finding_id)})"
        for finding_id, advisory in ctx.advisories
    ] or ["- none recorded"]
    sections = [
        "## Guardian remediation",
        "",
        f"- Case: {inline(case.id)} ({inline(case.priority.label)} priority)",
        f"- Title: {inline(case.title)}",
        f"- Branch: {inline(ctx.branch)} at {inline(ctx.commit_sha[:12])}",
        "",
        "### Findings fixed",
        "",
        *findings,
        "",
        "### Human decision",
        "",
        *_decision_lines(ctx),
        "",
        "### Change",
        "",
        *_candidate_lines(ctx),
        "",
        "### Validation (sandboxed install, build and test)",
        "",
        *_validation_lines(ctx),
        "",
        "### Verification (rescan, before and after)",
        "",
        *_verification_lines(ctx),
        *_ai_lines(ctx),
        "",
        "---",
        (
            "Generated by Guardian after human approval. Guardian never merges: review and merge "
            "this pull request yourself."
        ),
    ]
    body = "\n".join(sections) + "\n"
    if len(body) > MAX_BODY_CHARS:
        body = body[: MAX_BODY_CHARS - 40] + "\n\n_(truncated by Guardian)_\n"
    return body

"""Stage comments Guardian posts back to a case's Jira issue, plus optional transitions.

Every post is idempotent: the audit log records ``jira:comment:<stage>:<key>`` after a comment
is posted, and a stage whose event already exists is not posted again. That makes the
side-effecting nodes of the remediation graph safe to re-run after a resume.
"""

from collections.abc import Sequence
from typing import Literal

from guardian.core.config import GuardianSettings, JiraTransitionEvent
from guardian.core.remediation_models import (
    HumanDecision,
    JiraLink,
    ValidationRun,
    VerificationResult,
)
from guardian.integrations.github.records import pr_url_is_safe
from guardian.integrations.jira import adf
from guardian.integrations.jira.client import JiraClient, JiraError
from guardian.storage.database import Database
from guardian.storage.remediation import SYSTEM_ACTOR

Stage = Literal[
    "acknowledged", "applying", "validation", "verification", "failure", "pr_opened", "pr_failed"
]


def stage_event(stage: Stage, key: str) -> str:
    return f"jira:comment:{stage}:{key}"


def already_posted(db: Database, case_id: str, event: str) -> bool:
    return any(e.event == event for e in db.audit.list(case_id))


def comment_stage(  # noqa: PLR0913 - stage, body, idempotency key and optional transition
    db: Database,
    jira: JiraClient,
    link: JiraLink,
    stage: Stage,
    body_adf: adf.Node,
    *,
    key: str | None = None,
    settings: GuardianSettings | None = None,
    transition: JiraTransitionEvent | None = None,
) -> bool:
    """Post ``body_adf`` once per (stage, key); ``key`` defaults to the issue key, so pass a
    run-specific key (e.g. a validation attempt number) for stages that can repeat.

    Returns True when a comment was posted now. Afterwards, if ``transition`` names an event
    configured in ``settings.jira_transitions``, the issue is moved (best effort).
    """
    event = stage_event(stage, key or link.issue_key)
    if already_posted(db, link.case_id, event):
        return False
    comment_id = jira.add_comment(link.issue_key, body_adf)
    db.audit.append(
        link.case_id,
        event,
        SYSTEM_ACTOR,
        {"issue_key": link.issue_key, "comment_id": comment_id, "stage": stage},
    )
    if settings is not None and transition is not None:
        apply_transition(db, jira, settings, link, transition)
    return True


def apply_transition(
    db: Database,
    jira: JiraClient,
    settings: GuardianSettings,
    link: JiraLink,
    event: JiraTransitionEvent,
) -> bool:
    """Move the issue through the transition configured for ``event``; False when none is
    configured, the workflow does not offer it, or Jira refuses (comments stay primary)."""
    name = settings.jira_transitions.get(event)
    if not name:
        return False
    try:
        moved = jira.transition(link.issue_key, name)
    except JiraError as exc:
        db.audit.append(
            link.case_id,
            "jira:transition_failed",
            SYSTEM_ACTOR,
            {"issue_key": link.issue_key, "event": event, "error": str(exc)},
        )
        return False
    db.audit.append(
        link.case_id,
        "jira:transitioned" if moved else "jira:transition_unavailable",
        SYSTEM_ACTOR,
        {"issue_key": link.issue_key, "event": event, "transition": name},
    )
    return moved


# --- bodies -------------------------------------------------------------------------------


def acknowledged_body(decision: HumanDecision, summary: str) -> adf.Node:
    return adf.doc(
        adf.paragraph(
            adf.strong("Decision acknowledged: "),
            adf.code(summary),
            f" by {decision.actor_display} via {decision.channel}.",
        )
    )


def applying_body(branch: str, candidate_id: str | None = None) -> adf.Node:
    parts: list[adf.Inline] = [
        adf.strong("Applying the approved change "),
        "in an isolated worktree on branch ",
        adf.code(branch),
    ]
    if candidate_id:
        parts += [" (candidate ", adf.code(candidate_id), ")"]
    parts.append(". The default branch is never touched.")
    return adf.doc(adf.paragraph(*parts))


def validation_body(run: ValidationRun) -> adf.Node:
    rows = [
        [
            step.name,
            adf.tag(step.status.value),
            "-" if step.exit_code is None else str(step.exit_code),
            f"{step.duration_seconds:.1f}s",
            step.detail or "",
        ]
        for step in run.steps
    ]
    tests = (
        "no tests discovered"
        if not run.tests_discovered
        else f"{run.tests_passed or 0} passed, {run.tests_failed or 0} failed "
        f"of {run.tests_discovered}"
    )
    return adf.doc(
        adf.heading("Validation results", 3),
        adf.paragraph(
            "Branch ", adf.code(run.branch), " · sandbox ", adf.code(run.sandbox), f" · {tests}"
        ),
        adf.table(["Step", "Status", "Exit", "Duration", "Detail"], rows) if rows else None,
    )


def verification_body(result: VerificationResult) -> adf.Node:
    def fmt(value: float | None) -> str:
        return "unknown" if value is None else f"{value:.1f}"

    def count(items: Sequence[object]) -> str:
        return str(len(items))

    diff = result.sbom_diff
    rows: list[list[adf.Inline]] = [
        ["Risk score", fmt(result.risk_before), fmt(result.risk_after)],
        [
            "Targeted findings",
            str(len(result.target_findings_resolved) + len(result.findings_still_present)),
            f"{count(result.findings_still_present)} still present",
        ],
        ["New findings", "-", count(result.new_findings)],
        [
            "Components",
            "-",
            f"+{len(diff.added)} / -{len(diff.removed)} / ~{len(diff.changed)}",
        ],
    ]
    return adf.doc(
        adf.heading("Verification verdict", 3),
        adf.paragraph(adf.tag(result.status.value), f" · confidence {result.confidence.value}"),
        adf.table(["", "Before", "After"], rows),
        adf.bullet_list(list(result.reasons)),
    )


def failure_body(summary: str, reasons: Sequence[str] = ()) -> adf.Node:
    return adf.doc(
        adf.paragraph(adf.strong("Validation failed: "), summary),
        adf.bullet_list(list(reasons)),
        adf.paragraph(
            "The case is back in review. Reply with a /guardian command "
            "(e.g. /guardian modify version=<x.y.z> or /guardian decline ...)."
        ),
    )


def _link(url: str) -> adf.Node:
    """A link node, only for https://github.com/... (anything else stays plain code)."""
    if not pr_url_is_safe(url):
        return adf.code(url)
    node = adf.text(url)
    node["marks"] = [{"type": "link", "attrs": {"href": url}}]
    return node


def pr_opened_body(url: str, number: object, *, draft: bool, reused: bool = False) -> adf.Node:
    kind = "Draft pull request" if draft else "Pull request"
    verb = "found (already open)" if reused else "opened"
    return adf.doc(
        adf.paragraph(adf.strong(f"{kind} #{number} {verb}: "), _link(url)),
        adf.paragraph(
            "Guardian pushed only its guardian/fix-* branch after the human-approved fix was "
            "VERIFIED. Guardian never merges; review and merge it yourself."
        ),
    )


def pr_failed_body(error: str) -> adf.Node:
    return adf.doc(
        adf.paragraph(adf.strong("Pull request not opened: "), error),
        adf.paragraph(
            "The fix is still VERIFIED and committed on Guardian's local guardian/fix-* branch; "
            "push it and open the pull request by hand, or fix the cause and re-run."
        ),
    )

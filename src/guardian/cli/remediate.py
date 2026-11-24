"""``guardian remediate``, ``guardian cases`` and ``guardian case``: remediation cases.

Candidates and plans come from deterministic tools; an AI rationale is always labelled as
inference. Package names, advisory text and rationales are untrusted, so they are escaped.
"""

from pathlib import Path
from typing import Annotated

import typer
from rich.markup import escape
from rich.table import Table

from guardian.cli.common import cli_errors, console, err_console, open_database
from guardian.core.config import GuardianSettings
from guardian.core.models import Priority
from guardian.core.remediation_models import (
    AuditEvent,
    CaseStatus,
    RemediationActionType,
    RemediationCandidate,
    RemediationCase,
    RemediationPlan,
    ValidationRun,
    VerificationResult,
)
from guardian.integrations.github.records import pull_request_of
from guardian.remediation.cases import REFRESHABLE, create_cases
from guardian.remediation.registry import NpmRegistry
from guardian.remediation.runtime import start_cases
from guardian.storage.database import Database

PRIORITY_STYLES = {
    Priority.P1: "bold red",
    Priority.P2: "red",
    Priority.P3: "yellow",
    Priority.P4: "dim",
}
MAX_AUDIT_ROWS = 200


def build_registry(settings: GuardianSettings) -> NpmRegistry:
    return NpmRegistry(settings.data_dir / "cache" / "npm-registry")


def resolve_scan(db: Database, settings: GuardianSettings, scan_id: str) -> str:
    """Like ``ScanStore.resolve``, but ``latest`` skips Guardian's own verification rescans of
    fix worktrees (``<data_dir>/worktrees/...``), which are stored as scans too."""
    if scan_id != "latest":
        return db.scans.resolve(scan_id)
    worktrees = (settings.data_dir / "worktrees").resolve()
    for record in db.scans.recent(limit=200):
        if not Path(record.repository_root).resolve().is_relative_to(worktrees):
            return record.id
    return db.scans.resolve(scan_id)


def styled_priority(priority: Priority) -> str:
    style = PRIORITY_STYLES[priority]
    return f"[{style}]{priority.value} {priority.label}[/{style}]"


def describe(c: RemediationCandidate) -> str:
    """One-line, unescaped description of a candidate."""
    name = c.component.removeprefix("pkg:npm/").replace("%40", "@").rsplit("@", 1)[0]
    if c.action_type is RemediationActionType.BLOCK:
        return f"block {name} (Guardian denylist, no code change)"
    if c.action_type is RemediationActionType.ESCALATE:
        return "escalate to security review (no code change)"
    if c.action_type is RemediationActionType.REMOVE:
        return f"remove {name}"
    if c.strategy == "parent":
        return f"upgrade parent {c.target_package} {c.from_version} -> {c.to_version}"
    if c.strategy == "override":
        return f"override {name} {c.from_version} -> {c.to_version}"
    return f"{c.action_type.value.lower()} {name} {c.from_version} -> {c.to_version}"


def _reduction(c: RemediationCandidate) -> str:
    return "-" if c.expected_risk_reduction is None else f"-{c.expected_risk_reduction:g}"


def _verified(c: RemediationCandidate) -> str:
    if c.version_verified is None:
        return "-"
    return "[green]registry[/green]" if c.version_verified else "[yellow]unverified[/yellow]"


def candidates_table(
    candidates: list[RemediationCandidate], plan: RemediationPlan | None, title: str
) -> Table:
    table = Table(title=title, title_justify="left")
    table.add_column("")
    table.add_column("Candidate")
    table.add_column("Action", overflow="fold")
    table.add_column("Jump")
    table.add_column("Fixes")
    table.add_column("Risk", justify="right")
    table.add_column("Version")
    chosen = plan.chosen_candidate_id if plan else None
    for c in _ordered(candidates, plan):
        total = len(c.finding_ids)
        table.add_row(
            "[bold green]*[/bold green]" if c.id == chosen else "",
            c.id,
            escape(describe(c)),
            c.semver_jump.value if c.to_version else "-",
            f"{len(c.fixes_finding_ids)}/{total}",
            _reduction(c),
            _verified(c),
        )
    return table


def _ordered(
    candidates: list[RemediationCandidate], plan: RemediationPlan | None
) -> list[RemediationCandidate]:
    """Plan order (chosen, then alternatives); candidates the plan does not list come last."""
    if plan is None:
        return candidates
    by_id = {c.id: c for c in candidates}
    order = [plan.chosen_candidate_id, *plan.alternatives]
    listed = [by_id[i] for i in order if i in by_id]
    return listed + [c for c in candidates if c.id not in set(order)]


def print_plan(plan: RemediationPlan) -> None:
    if plan.decided_by == "llm":
        model = "/".join(p for p in (plan.llm_provider, plan.llm_model) if p) or "LLM"
        console.print(
            f"[bold magenta]AI inference[/bold magenta] ({escape(model)}, confidence "
            f"{plan.confidence.value}):"
        )
    else:
        console.print(
            f"[bold]Deterministic plan[/bold] (verified, confidence {plan.confidence.value}):"
        )
    console.print(f"  {plan.rationale}", markup=False)
    for note in plan.notes:
        console.print(f"  note: {note}", style="dim", markup=False)


def _print_case_summary(case: RemediationCase, db: Database) -> None:
    store = db.remediation
    candidates = store.candidates(case.id)
    plan = store.plan(case.id)
    console.rule(f"{styled_priority(case.priority)} {case.id}  {escape(case.title)}")
    console.print(f"Status: {case.status.value}")
    by_id = {c.id: c for c in candidates}
    chosen = by_id.get(plan.chosen_candidate_id) if plan else None
    if chosen is not None:
        console.print(
            f"Recommended: [bold]{escape(describe(chosen))}[/bold] ({chosen.id}), expected risk "
            f"reduction {_reduction(chosen)}, fixes {len(chosen.fixes_finding_ids)}/"
            f"{len(chosen.finding_ids)} finding(s)"
        )
    if plan is not None:
        print_plan(plan)
    console.print(candidates_table(candidates, plan, "Candidates (* = recommended)"))


def remediate(  # noqa: PLR0913, PLR0917 - one parameter per CLI option
    scan_id: Annotated[str, typer.Argument(help="Scan id, unique prefix, or 'latest'.")] = "latest",
    finding: Annotated[
        list[str] | None,
        typer.Option("--finding", "-f", help="Only the case(s) containing this finding id."),
    ] = None,
    top: Annotated[int, typer.Option("--top", min=1, help="At most this many cases.")] = 5,
    min_priority: Annotated[
        str, typer.Option("--min-priority", help="P1-P4 or critical/high/medium/low.")
    ] = "HIGH",
    no_ai: Annotated[
        bool, typer.Option("--no-ai", help="Deterministic plan; no LLM call.")
    ] = False,
    no_jira: Annotated[
        bool, typer.Option("--no-jira", help="Do not publish the cases to Jira.")
    ] = False,
) -> None:
    """Create remediation cases (npm) for a scan and start their review workflow.

    Each case gets candidates, a plan and alternatives, then its remediation graph runs up to the
    human decision (publishing to Jira when configured, unless --no-jira).
    """
    try:
        floor = Priority.parse(min_priority)
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="--min-priority") from None
    settings = GuardianSettings()
    with cli_errors():
        with open_database(settings) as db:
            resolved = resolve_scan(db, settings, scan_id)
            created = create_cases(
                db,
                resolved,
                settings=settings,
                registry=build_registry(settings),
                min_priority=floor,
                top=top,
                finding_ids=finding or None,
                no_ai=no_ai,
            )
        if not created:
            target = "the given finding(s)" if finding else f"priority {floor.label} or higher"
            console.print(f"No npm vulnerability cases for {target} in scan {resolved[:12]}.")
            return
        open_ids = [c.id for c in created if c.status in REFRESHABLE]
        started = start_cases(settings, open_ids, jira_enabled=not no_jira) if open_ids else []
        with open_database(settings) as db:
            for item in created:
                _print_case_summary(db.remediation.get(item.id), db)
    for result in started:
        if result.error:
            err_console.print(
                f"[red]error:[/red] {result.case_id}: workflow not started: {escape(result.error)}"
            )
    awaiting = sum(1 for r in started if r.interrupt is not None)
    published = sorted({r.jira_key for r in started if r.jira_key})
    jira_note = f"; Jira: {', '.join(published)}" if published else ""
    console.print(
        f"{len(created)} case(s), {awaiting} waiting for a decision{escape(jira_note)}. "
        "Details: [bold]guardian case <ID>[/bold]; decide with [bold]guardian decide <ID> "
        "accept|modify|decline[/bold], Jira or [bold]guardian ui[/bold]; "
        "nothing is applied without a recorded human decision."
    )


def cases(
    status: Annotated[
        CaseStatus | None, typer.Option("--status", "-s", help="Only cases in this state.")
    ] = None,
) -> None:
    """List remediation cases."""
    with cli_errors(), open_database() as db:
        rows = db.remediation.list(status)
    if not rows:
        console.print("No remediation cases" + (f" in {status.value}." if status else "."))
        return
    table = Table(title="Remediation cases", title_justify="left")
    table.add_column("ID")
    table.add_column("Priority")
    table.add_column("Status")
    table.add_column("Case", overflow="fold")
    table.add_column("Jira")
    table.add_column("Updated")
    for case in sorted(rows, key=lambda c: (c.priority.value, c.created_at)):
        table.add_row(
            case.id,
            styled_priority(case.priority),
            case.status.value,
            escape(case.title),
            escape(case.jira_key or "-"),
            case.updated_at.strftime("%Y-%m-%d %H:%M"),
        )
    console.print(table)


def case(
    case_id: Annotated[str, typer.Argument(help="Remediation case id (rc_...).")],
) -> None:
    """Show one case: candidates, plan, decisions, validation and the audit trail."""
    with cli_errors(), open_database() as db:
        item = db.remediation.get(case_id)
        _print_case_summary(item, db)
        candidates = db.remediation.candidates(item.id)
        plan = db.remediation.plan(item.id)
        decisions = db.remediation.decisions(item.id)
        validations = db.remediation.validations(item.id)
        verifications = db.remediation.verifications(item.id)
        events = db.audit.list(item.id)
    console.print(
        f"Scan: {item.scan_id[:12]}  Repository: {escape(item.repository_root)}  "
        f"Jira: {escape(item.jira_key or '-')}"
    )
    console.print("Findings: " + ", ".join(item.finding_ids), markup=False)

    console.print("\n[bold]Candidate details[/bold] (verified facts)")
    for c in _ordered(candidates, plan):
        console.print(f"  {c.id}  {describe(c)}", markup=False)
        for note in c.compatibility_notes:
            console.print(f"      - {note}", markup=False)
        console.print(f"      rollback: {c.rollback}", markup=False)

    console.print("\n[bold]Decisions[/bold]")
    if not decisions:
        console.print("  none recorded yet")
    for d in decisions:
        extra = f" {d.decline_reason.value}" if d.decline_reason else ""
        target = f" candidate={d.candidate_id}" if d.candidate_id else ""
        console.print(
            f"  {d.decided_at:%Y-%m-%d %H:%M} {d.decision.value}{extra}{target} by "
            f"{d.actor_display} via {d.channel}",
            markup=False,
        )
        if d.justification:
            console.print(f"      {d.justification}", markup=False)
    _print_validations(validations)
    _print_verifications(verifications)
    _print_pull_request(events)

    console.print("\n[bold]Audit trail[/bold]")
    table = Table(show_header=True)
    table.add_column("At")
    table.add_column("Event", overflow="fold")
    table.add_column("Actor")
    table.add_column("Hash")
    for event in events[-MAX_AUDIT_ROWS:]:
        table.add_row(
            event.at.strftime("%Y-%m-%d %H:%M:%S"),
            escape(event.event),
            escape(event.actor),
            event.event_sha256[:12],
        )
    console.print(table)


def _print_pull_request(events: list[AuditEvent]) -> None:
    pr = pull_request_of(events)
    if pr is None:
        return
    console.print("\n[bold]Pull request[/bold]")
    if pr.get("url"):
        kind = "draft " if pr.get("draft") else ""
        console.print(
            f"  {kind}#{pr.get('number')} {pr['url']} (base {pr.get('base') or '?'}); "
            "Guardian never merges",
            markup=False,
        )
    else:
        console.print(f"  not opened: {pr.get('error')}", markup=False)


def _print_validations(validations: list[ValidationRun]) -> None:
    console.print("\n[bold]Validation runs[/bold]")
    if not validations:
        console.print("  none yet")
    for run in validations:
        tests = (
            f", tests {run.tests_passed or 0}/{run.tests_discovered} passed"
            if run.tests_discovered
            else ""
        )
        console.print(
            f"  {run.started_at:%Y-%m-%d %H:%M} {run.branch} @ {(run.commit_sha or '-')[:12]} "
            f"sandbox={run.sandbox}{tests}",
            markup=False,
        )
        for step in run.steps:
            exit_code = "" if step.exit_code is None else f" exit {step.exit_code}"
            conflict = (
                " [known conflict: intentional challenge code]" if step.known_conflict else ""
            )
            console.print(
                f"      {step.name}: {step.status.value}{exit_code} "
                f"({step.duration_seconds:.1f}s){conflict}",
                markup=False,
            )
            if step.detail:
                console.print(f"          {step.detail}", markup=False)
            if step.log_path:
                console.print(f"          log: {step.log_path}", markup=False)


def _risk(value: float | None) -> str:
    return "unknown" if value is None else f"{value:.1f}"


def _print_verifications(verifications: list[VerificationResult]) -> None:
    console.print("\n[bold]Verification[/bold]")
    if not verifications:
        console.print("  none yet")
    for result in verifications:
        diff = result.sbom_diff
        console.print(
            f"  {result.status.value} (confidence {result.confidence.value}); scan "
            f"{result.before_scan_id[:12]} -> {(result.after_scan_id or '-')[:12]}; risk "
            f"{_risk(result.risk_before)} -> {_risk(result.risk_after)}",
            markup=False,
        )
        console.print(
            f"      resolved {len(result.target_findings_resolved)}, still present "
            f"{len(result.findings_still_present)}, new {len(result.new_findings)}; "
            f"components +{len(diff.added)} -{len(diff.removed)} ~{len(diff.changed)}",
            markup=False,
        )
        for change in diff.changed:
            console.print(
                f"      {change.purl_base}: {change.from_version} -> {change.to_version}",
                markup=False,
            )
        for reason in result.reasons:
            console.print(f"      - {reason}", markup=False)

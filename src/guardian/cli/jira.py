"""``guardian jira``: publish remediation cases, sync decisions, check the connection."""

from collections.abc import Callable
from typing import Annotated

import typer
from rich.markup import escape
from rich.table import Table

from guardian.cli.common import cli_errors, console, err_console, open_database
from guardian.cli.decide import print_run_result
from guardian.core.config import GuardianSettings, env_files
from guardian.core.remediation_models import HumanDecision, RemediationCase
from guardian.integrations.jira.client import JiraClient, JiraError, jira_client_from_settings
from guardian.integrations.jira.publish import CaseContext, load_case_contexts, publish_cases
from guardian.integrations.jira.sync import JiraSync, SyncReport
from guardian.llm.providers import mask_secret
from guardian.remediation.runtime import submit_decision
from guardian.storage.database import Database

jira_app = typer.Typer(
    name="jira",
    help="Publish remediation cases to Jira and sync human decisions back.",
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,  # never dump settings (API token) into tracebacks
)


def load_settings() -> GuardianSettings:
    return GuardianSettings(_env_file=env_files())


def make_client(settings: GuardianSettings) -> JiraClient:
    """Indirection so tests can inject a client backed by ``httpx.MockTransport``."""
    return jira_client_from_settings(settings)


def scan_contexts(db: Database, scan_id: str) -> dict[str, CaseContext]:
    """Case id -> what its issue describes (see ``load_case_contexts``)."""
    return load_case_contexts(db, scan_id)


@jira_app.command()
def push(
    scan_id: Annotated[str, typer.Argument(help="Scan id, unique prefix, or 'latest'.")] = "latest",
) -> None:
    """Create or update Jira issues for a scan's remediation cases (top N, >= min priority)."""
    with cli_errors():
        settings = load_settings()
        jira = make_client(settings)
        with open_database(settings) as db:
            resolved = db.scans.resolve(scan_id)
            cases = [c for c in db.remediation.list() if c.scan_id == resolved]
            if not cases:
                console.print(
                    f"No remediation cases for scan {resolved[:12]}. "
                    "Run [bold]guardian remediate[/bold] first."
                )
                return
            contexts = scan_contexts(db, resolved)

            def load(case: RemediationCase) -> CaseContext:
                return contexts.get(case.id) or CaseContext([], [], [], None)

            report = publish_cases(db, jira, settings, cases, load)
    table = Table(title=f"Jira issues for scan {resolved[:12]}", title_justify="left")
    for column in ("Case", "Issue"):
        table.add_column(column)
    for link in report.links:
        table.add_row(link.case_id, escape(link.issue_key))
    console.print(table)
    console.print(
        f"{len(report.links)} published/updated, {len(report.skipped)} skipped "
        f"(below {settings.jira_min_priority.label.upper()} or beyond the cap of "
        f"{settings.jira_max_issues})."
    )
    for case_id, error in report.errors:
        err_console.print(f"[red]error:[/red] {case_id}: {escape(error)}")
    if report.errors:
        raise typer.Exit(code=1)


def _print_report(report: SyncReport) -> None:
    console.print(
        f"issues {report.issues_seen} · comments {report.comments_seen} · "
        f"decisions {len(report.decisions)} · parse errors {report.parse_errors} · "
        f"unauthorized {report.unauthorized} · ignored in state {report.wrong_state}"
    )
    for decision in report.decisions:
        console.print(
            f"  {decision.case_id}: {decision.decision.value} by "
            f"{escape(decision.actor_display)} (comment {decision.jira_comment_id})"
        )
    for error in report.errors:
        err_console.print(f"[red]error:[/red] {escape(error)}")


def graph_handler(settings: GuardianSettings) -> Callable[[RemediationCase, HumanDecision], None]:
    """Resume the case's remediation graph with a decision the sync already recorded."""

    def handle(case: RemediationCase, decision: HumanDecision) -> None:
        console.print(
            f"  {case.id}: {decision.decision.value} from Jira; resuming the remediation graph ..."
        )
        print_run_result(
            settings, submit_decision(settings, case.id, decision, already_recorded=True)
        )

    return handle


@jira_app.command()
def sync(
    watch: Annotated[
        bool, typer.Option("--watch", "-w", help="Keep polling every GUARDIAN_JIRA_POLL_SECONDS.")
    ] = False,
) -> None:
    """Read /guardian decisions from Jira comments and resume each case's remediation graph."""
    with cli_errors():
        settings = load_settings()
        jira = make_client(settings)
        with open_database(settings) as db:
            syncer = JiraSync(db, jira, settings, on_decision=graph_handler(settings))
            if watch:
                console.print(
                    f"Polling Jira every {settings.jira_poll_seconds:g}s; Ctrl-C to stop."
                )
                syncer.watch(on_report=_print_report)
                return
            report = syncer.sync_once()
    _print_report(report)
    if report.errors:
        raise typer.Exit(code=1)


@jira_app.command()
def status() -> None:
    """Show the Jira configuration (token masked) and check authentication."""
    with cli_errors():
        settings = load_settings()
    table = Table(title="Guardian Jira", title_justify="left")
    table.add_column("Setting")
    table.add_column("Value")
    table.add_row("JIRA_BASE_URL", escape(str(settings.jira_base_url or "not set")))
    table.add_row("JIRA_EMAIL", escape(settings.jira_email or "not set"))
    table.add_row("JIRA_API_TOKEN", mask_secret(settings.jira_api_token))
    table.add_row("JIRA_PROJECT_KEY", escape(settings.jira_project_key or "not set"))
    table.add_row("Issue type", escape(settings.jira_issue_type))
    table.add_row("Approvers", str(len(settings.approvers)))
    table.add_row("CLI approvers", escape(", ".join(settings.cli_approvers) or "none"))
    table.add_row(
        "Publish",
        f">= {settings.jira_min_priority.label.upper()}, at most {settings.jira_max_issues}",
    )
    console.print(table)
    with cli_errors():
        jira = make_client(settings)
        try:
            me = jira.myself()
        except JiraError as exc:
            err_console.print(f"[red]Authentication failed:[/red] {escape(str(exc))}")
            raise typer.Exit(code=1) from None
    name = me.get("displayName") or me.get("emailAddress") or "?"
    console.print(
        f"[green]Authenticated[/green] as {escape(str(name))} "
        f"(accountId {escape(str(me.get('accountId', '?')))})"
    )

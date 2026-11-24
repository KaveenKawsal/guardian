"""``guardian decide`` and ``guardian validate``: hand a human decision to the remediation graph.

The arguments are turned back into a ``/guardian ...`` line and parsed by the same strict
parser the Jira sync uses; the approver is the local OS user, checked against
``GUARDIAN_CLI_APPROVERS``. The decision is then submitted through
``runtime.submit_decision``: the case's LangGraph thread resumes and runs
apply -> sandbox build/test -> rescan -> verdict (or records the decline) before this returns.
"""

import getpass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated

import typer
from rich.markup import escape

from guardian.cli.common import cli_errors, console, err_console, open_database
from guardian.core.config import GuardianSettings, env_files
from guardian.core.remediation_models import DecisionType
from guardian.integrations.decisions import decision_applies, revalidate_ready
from guardian.integrations.jira.authz import is_authorized_cli
from guardian.integrations.jira.commands import (
    GRAMMAR_HELP,
    CommandParseError,
    describe,
    parse_command,
    to_decision,
)
from guardian.orchestration.remediation_graph import RunResult
from guardian.remediation.runtime import case_has_crashed_step, retry_case, submit_decision


class Action(StrEnum):
    accept = "accept"
    modify = "modify"
    decline = "decline"
    revalidate = "revalidate"


def command_line(action: str, args: list[str], justification: str | None) -> str:
    """Rebuild ``/guardian <action> key=value ... [-- justification]``.

    The shell consumes a literal ``--``, so for ``decline`` everything from the first token
    without ``=`` on is taken as the justification, as is ``--justification``.
    """
    keys: list[str] = []
    free: list[str] = []
    separated = False
    for arg in args:
        if separated:
            free.append(arg)
        elif arg == "--" or (action == "decline" and "=" not in arg):
            separated = True
            free.extend([] if arg == "--" else [arg])
        else:
            keys.append(arg)
    reason = " ".join([*free, (justification or "").strip()]).strip()
    line = " ".join(["/guardian", action, *keys])
    if separated or reason:
        line += " -- " + reason
    return line


def current_user() -> str:
    return getpass.getuser()


def load_settings() -> GuardianSettings:
    return GuardianSettings(_env_file=env_files())


def decide(
    case_id: Annotated[str, typer.Argument(help="Remediation case id (rc_...).")],
    action: Annotated[Action, typer.Argument(help="accept | modify | decline | revalidate")],
    args: Annotated[
        list[str] | None,
        typer.Argument(help="key=value arguments, e.g. version=1.2.3 or reason=wont_fix."),
    ] = None,
    justification: Annotated[
        str | None, typer.Option("--justification", "-j", help="Why (required for accepted_risk).")
    ] = None,
) -> None:
    """Record an accept/modify/decline/revalidate decision for a case (channel=cli)."""
    line = command_line(action.value, list(args or []), justification)
    user = current_user()
    with cli_errors():
        settings = load_settings()
        with open_database(settings) as db:
            case = db.remediation.get(case_id)
            if not is_authorized_cli(user, settings):
                db.audit.append(case.id, "cli:unauthorized", f"cli:{user}", {"command": line})
                err_console.print(
                    f"[red]error:[/red] local user {escape(user)!r} is not in "
                    "GUARDIAN_CLI_APPROVERS; decision not recorded."
                )
                raise typer.Exit(code=3)
            try:
                parsed = parse_command(line)
            except CommandParseError as exc:
                err_console.print(f"[red]error:[/red] {escape(str(exc))}")
                err_console.print(escape(GRAMMAR_HELP))
                raise typer.Exit(code=2) from None
            if not decision_applies(
                case, parsed.decision, can_revalidate=revalidate_ready(db, case.id)
            ):
                err_console.print(
                    f"[red]error:[/red] case is {case.status.value}; decision ignored."
                )
                raise typer.Exit(code=2)
            decision = to_decision(
                parsed,
                case_id=case.id,
                actor_id=user,
                actor_display=user,
                channel="cli",
                comment_id=None,
                at=datetime.now(UTC),
            )
        console.print(
            f"Decision: [bold]{escape(describe(parsed))}[/bold] by {escape(user)}. "
            + (
                "Recording it."
                if parsed.decision is DecisionType.DECLINE
                else "Applying in an isolated worktree, then sandboxed build/test and a "
                "rescan; this can take several minutes ..."
            )
        )
        result = submit_decision(settings, case.id, decision)
        print_run_result(settings, result)


def print_run_result(settings: GuardianSettings, result: RunResult) -> None:
    """Status, verdict and reasons after a graph run."""
    with open_database(settings) as db:
        case = db.remediation.get(result.case_id)
    console.print(f"Case {case.id} is now [bold]{case.status.value}[/bold].")
    values = result.values
    verification = values.get("verification") or {}
    if verification.get("status"):
        console.print(
            f"Verdict: [bold]{escape(str(verification['status']))}[/bold] "
            f"(confidence {escape(str(verification.get('confidence', '?')))}); "
            f"risk {verification.get('risk_before')} -> {verification.get('risk_after')}"
        )
        for reason in verification.get("reasons") or []:
            console.print(f"  - {reason}", markup=False)
    validation = values.get("validation") or {}
    for step in validation.get("steps") or []:
        detail = f" ({step.get('detail')})" if step.get("detail") else ""
        console.print(f"  {step.get('name')}: {step.get('status')}{detail}", markup=False)
    if values.get("error") and result.interrupt is not None:
        console.print(f"[yellow]Returned to review:[/yellow] {escape(str(values['error']))}")
    if result.interrupt is not None:
        console.print(
            "Waiting for a new decision: [bold]guardian decide "
            f"{case.id} modify|decline|revalidate ...[/bold]"
        )
    elif result.finished:
        console.print("Case closed.")


def validate(
    case_id: Annotated[str, typer.Argument(help="Remediation case id (rc_...).")],
) -> None:
    """Re-run validation for a case: retry a crashed step, or submit REVALIDATE after a failure.

    REVALIDATE re-applies the last ACCEPT/MODIFY decision in a fresh worktree, then builds,
    tests and rescans again. It needs the case back in review after a failed attempt.
    """
    with cli_errors():
        settings = load_settings()
        if case_has_crashed_step(settings, case_id):
            console.print(f"Retrying the interrupted step of {escape(case_id)} ...")
            result = retry_case(settings, case_id)
            print_run_result(settings, result)
            return
    decide(case_id, Action.revalidate, None, None)

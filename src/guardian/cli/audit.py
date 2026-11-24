"""``guardian audit``: check the hash-chained remediation audit log."""

import typer
from rich.markup import escape

from guardian.cli.common import cli_errors, console, err_console, open_database

audit_app = typer.Typer(
    name="audit",
    help="Inspect the append-only, hash-chained remediation audit log.",
    no_args_is_help=True,
)


@audit_app.command()
def verify() -> None:
    """Recompute every audit event hash and chain link; exit 1 when anything was tampered with."""
    with cli_errors(), open_database() as db:
        ok, problems = db.audit.verify()
        count = len(db.audit.list())
    if ok:
        console.print(f"[green]ok[/green]: {count} audit event(s), hash chain intact.")
        return
    err_console.print(f"[red]{len(problems)} problem(s)[/red] in {count} audit event(s):")
    for problem in problems:
        err_console.print(f"  - {escape(problem)}")
    raise typer.Exit(code=1)

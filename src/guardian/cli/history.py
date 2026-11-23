"""``guardian history``: list previous scans."""

from pathlib import Path
from typing import Annotated

import typer
from rich.markup import escape
from rich.table import Table

from guardian.cli.common import cli_errors, console, open_database, styled_status


def history(
    path: Annotated[Path | None, typer.Argument(help="Only show scans of this repository.")] = None,
    limit: Annotated[int, typer.Option("--limit", "-n", min=1, help="Number of scans.")] = 20,
) -> None:
    """List recent scans, newest first."""
    root = str(path.expanduser().resolve()) if path is not None else None
    with cli_errors(), open_database() as db:
        records = db.scans.recent(root, limit=limit)

    if not records:
        console.print("No scans recorded yet. Run [bold]guardian scan <path>[/bold].")
        return
    table = Table(title="Guardian scans", title_justify="left")
    for column in ("Scan", "Repository", "Started (UTC)", "Status", "Components", "Commit"):
        table.add_column(column)
    for r in records:
        table.add_row(
            r.id[:12],
            escape(r.repository_name),
            r.started_at.strftime("%Y-%m-%d %H:%M"),
            styled_status(r.status.value),
            str(r.component_count),
            r.git_commit[:10] if r.git_commit else "-",
        )
    console.print(table)

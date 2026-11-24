"""``guardian analyze``: one command from a repository to the review website.

    scan (or reuse a scan of the same commit) -> AI investigators -> remediation cases
    -> review console in the browser

Every step is the existing command (``scan``, ``investigate``, ``remediate``, ``ui``) so the
behaviour, safety checks and output are the same as running them by hand. Nothing is changed
in the repository: fixes are applied only after a human clicks Accept in the console, and then
only in a ``guardian/fix-*`` worktree, built and tested in the Docker sandbox.
"""

from pathlib import Path
from typing import Annotated

import typer
from rich.markup import escape

from guardian.cli.common import console, err_console, open_database
from guardian.cli.investigate import investigate
from guardian.cli.remediate import remediate
from guardian.cli.scan import resolve_target, scan
from guardian.cli.ui import ui
from guardian.core.config import GuardianSettings
from guardian.core.models import ScanRecord, ScanStatus
from guardian.core.profiler import RepositoryProfiler
from guardian.investigation.runner import DEFAULT_MAX_CALLS
from guardian.sources.remote import RemoteTarget

_REUSABLE = frozenset({ScanStatus.COMPLETED, ScanStatus.PARTIAL})


def _step(number: int, total: int, title: str) -> None:
    console.rule(f"[bold]{number}/{total} {escape(title)}[/bold]")


def reusable_scan(settings: GuardianSettings, path: Path) -> ScanRecord | None:
    """The latest finished scan of ``path`` at its current, clean HEAD (None if anything differs).

    A dirty working tree is never reused: the scan would not describe what is on disk.
    """
    root = path.resolve()
    git = RepositoryProfiler(settings).git_info(root)
    if not git.is_repository or git.head_commit is None or git.is_dirty is not False:
        return None
    with open_database(settings) as db:
        for record in db.scans.recent(repository_root=str(root), limit=5):
            if record.status in _REUSABLE and record.git_commit == git.head_commit:
                return record
    return None


def analyze(  # noqa: PLR0913, PLR0917 - one parameter per CLI option
    target: Annotated[
        str | None,
        typer.Argument(help="Local path or repository URL to analyse.", show_default=False),
    ] = None,
    top: Annotated[
        int, typer.Option("--top", min=1, max=25, help="At most this many remediation cases.")
    ] = 5,
    min_priority: Annotated[
        str, typer.Option("--min-priority", help="P1-P4 or critical/high/medium/low.")
    ] = "HIGH",
    no_ai: Annotated[
        bool, typer.Option("--no-ai", help="Skip the AI investigators; deterministic plans.")
    ] = False,
    max_calls: Annotated[
        int, typer.Option("--max-calls", min=0, max=500, help="Cap on LLM calls.")
    ] = DEFAULT_MAX_CALLS,
    jira: Annotated[
        bool, typer.Option("--jira/--no-jira", help="Also publish the cases to Jira.")
    ] = False,
    rescan: Annotated[
        bool,
        typer.Option("--rescan", help="Scan again even if this commit was already scanned (slow)."),
    ] = False,
    port: Annotated[
        int, typer.Option("--port", "-p", min=0, max=65535, help="Console port on 127.0.0.1.")
    ] = 8765,
    no_open: Annotated[
        bool, typer.Option("--no-open", help="Print the console URL instead of opening it.")
    ] = False,
) -> None:
    """Analyse a repository end to end and open the review website.

    Scans the code base, runs the AI investigators, prepares recommended fixes, then opens the
    local console. Fixes run only when you accept them there: Guardian applies the change in an
    isolated git worktree, builds and tests it in the Docker sandbox, rescans and shows a verdict.
    """
    settings = GuardianSettings()
    total = 4
    source = resolve_target(target, None)
    reused = None
    if not rescan and not isinstance(source, RemoteTarget):
        reused = reusable_scan(settings, source.path)

    _step(1, total, "Scan")
    if reused is not None:
        console.print(
            f"Reusing scan [bold]{reused.id[:12]}[/bold] of {escape(reused.repository_root)} "
            f"at commit {(reused.git_commit or '')[:12]} ({reused.finding_count} findings). "
            "Pass --rescan to scan again.",
            highlight=False,
        )
        scan_id = reused.id
    else:
        scan(target=target if isinstance(source, RemoteTarget) else str(source.path))
        with open_database(settings) as db:
            latest = db.scans.recent(limit=1)
        if not latest or latest[0].status is ScanStatus.FAILED:
            err_console.print("[red]error:[/red] the scan failed; see the output above.")
            raise typer.Exit(code=1)
        scan_id = latest[0].id

    _step(2, total, "AI investigators" + (" (skipped: --no-ai)" if no_ai else ""))
    if not no_ai:
        try:
            investigate(scan_id=scan_id, top=top, no_ai=False, max_calls=max_calls)
        except typer.Exit as exc:
            if exc.exit_code:
                err_console.print(
                    "[yellow]warning:[/yellow] the AI investigation failed; continuing with "
                    "verified facts only."
                )

    _step(3, total, "Recommended fixes")
    remediate(
        scan_id=scan_id,
        finding=None,
        top=top,
        min_priority=min_priority,
        no_ai=no_ai,
        no_jira=not jira,
    )

    _step(4, total, "Review website")
    console.print(
        "Open a case and click [bold]Accept[/bold] to fix it: Guardian applies the change in an "
        "isolated worktree, builds and tests it in the Docker sandbox, rescans and shows the "
        "verdict. Several cases can be fixed at once; each runs in its own sandbox.",
    )
    ui(port=port, no_open=no_open)

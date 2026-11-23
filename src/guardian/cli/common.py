"""Helpers shared by CLI commands."""

from collections.abc import Generator
from contextlib import contextmanager

import typer
from rich.console import Console

from guardian.core.config import GuardianSettings
from guardian.core.exceptions import GuardianError
from guardian.storage.database import Database

console = Console()
err_console = Console(stderr=True)


@contextmanager
def open_database(settings: GuardianSettings | None = None) -> Generator[Database]:
    settings = settings or GuardianSettings()
    with Database(settings.database_path) as db:
        yield db


@contextmanager
def cli_errors() -> Generator[None]:
    """Turn expected Guardian errors into a one-line message and exit code 2."""
    try:
        yield
    except GuardianError as exc:
        err_console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=2) from exc


STATUS_STYLES = {
    "completed": "green",
    "success": "green",
    "partial": "yellow",
    "skipped": "dim",
    "running": "cyan",
}


def styled_status(status: str) -> str:
    style = STATUS_STYLES.get(status, "red")
    return f"[{style}]{status}[/{style}]"

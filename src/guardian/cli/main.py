"""Guardian command-line entry point."""

from typing import Annotated

import typer

from guardian import __version__
from guardian.cli.deps import deps
from guardian.cli.doctor import doctor
from guardian.cli.findings import explain, findings
from guardian.cli.graph import graph
from guardian.cli.history import history
from guardian.cli.profile import profile
from guardian.cli.scan import scan

app = typer.Typer(
    name="guardian",
    help="Guardian: AI-powered repository security intelligence.",
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,  # never dump scanned data or settings into tracebacks
)


def _version(value: bool) -> None:
    if value:
        typer.echo(f"guardian {__version__}")
        raise typer.Exit


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version, is_eager=True, help="Show version and exit."),
    ] = False,
) -> None:
    """Guardian: AI-powered repository security intelligence."""


app.command()(scan)
app.command()(findings)
app.command()(explain)
app.command()(history)
app.command()(deps)
app.command()(graph)
app.command()(profile)
app.command()(doctor)

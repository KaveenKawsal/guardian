"""Guardian command-line entry point."""

import sys
from typing import Annotated

import typer

from guardian import __version__
from guardian.cli.ai import ai_app
from guardian.cli.code import code
from guardian.cli.deps import deps
from guardian.cli.doctor import doctor
from guardian.cli.findings import explain, findings
from guardian.cli.graph import graph
from guardian.cli.history import history
from guardian.cli.profile import profile
from guardian.cli.report import report
from guardian.cli.scan import scan
from guardian.cli.shell import run_shell, shell

app = typer.Typer(
    name="guardian",
    help="Guardian: AI-powered repository security intelligence.",
    invoke_without_command=True,  # plain `guardian` starts the shell in a terminal
    pretty_exceptions_show_locals=False,  # never dump scanned data or settings into tracebacks
)


def _version(value: bool) -> None:
    if value:
        typer.echo(f"guardian {__version__}")
        raise typer.Exit


@app.callback()
def main(
    ctx: typer.Context,
    version: Annotated[  # noqa: ARG001 - handled by its eager callback
        bool,
        typer.Option("--version", callback=_version, is_eager=True, help="Show version and exit."),
    ] = False,
) -> None:
    """Guardian: AI-powered repository security intelligence.

    Run without a command in a terminal to start the interactive shell.
    """
    _tolerant_output()
    if ctx.invoked_subcommand is not None:
        return
    if _interactive():
        run_shell()
        return
    typer.echo(ctx.get_help())
    raise typer.Exit(code=2)  # as before (no_args_is_help): scripts see a usage exit code


def _tolerant_output() -> None:
    """Never crash on text the console cannot encode (e.g. cp1252 on Windows).

    Scanned repositories and LLM answers can contain any Unicode character.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="replace")


def _interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


app.command()(scan)
app.command()(findings)
app.command()(explain)
app.command()(history)
app.command()(deps)
app.command()(code)
app.command()(graph)
app.command()(profile)
app.command()(doctor)
app.command()(report)
app.command()(shell)
app.add_typer(ai_app)

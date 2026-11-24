"""``guardian ui``: local review console, the backup for Jira during a demo.

Binds 127.0.0.1 only. Decisions recorded here use the same parser and approver allowlist as
``guardian decide`` (``GUARDIAN_CLI_APPROVERS``) and are stored with ``channel="cli"``.
"""

import webbrowser
from typing import Annotated

import typer
from rich.markup import escape

from guardian.cli.common import cli_errors, console, err_console
from guardian.core.config import GuardianSettings, env_files
from guardian.remediation.runtime import make_ui_decision_handler
from guardian.ui.decisions import DecisionHandler, current_user
from guardian.ui.server import DEFAULT_PORT, ConsoleApp, make_server


def load_settings() -> GuardianSettings:
    return GuardianSettings(_env_file=env_files())


def decision_handler(settings: GuardianSettings) -> DecisionHandler | None:
    """The remediation graph resume. The UI has already saved and audited the decision and calls
    this on a worker thread (``submit_decision`` opens its own connections there)."""
    return make_ui_decision_handler(settings)


def ui(
    port: Annotated[
        int, typer.Option("--port", "-p", min=0, max=65535, help="Port on 127.0.0.1.")
    ] = DEFAULT_PORT,
    no_open: Annotated[
        bool, typer.Option("--no-open", help="Print the URL instead of opening a browser.")
    ] = False,
) -> None:
    """Open the local review console to record decisions when Jira is unavailable."""
    with cli_errors():
        settings = load_settings()
        app = ConsoleApp(settings, port=port, handler=decision_handler(settings))
        try:
            server = make_server(app, port)
        except OSError as exc:
            err_console.print(f"[red]error:[/red] cannot listen on 127.0.0.1:{port} ({exc}).")
            raise typer.Exit(code=2) from exc

    user = current_user()
    console.print("Guardian review console (local only). Open:")
    console.print(app.launch_url, markup=False, highlight=False, soft_wrap=True)
    if user not in settings.cli_approvers:
        console.print(
            f"[yellow]Local user {escape(repr(user))} is not in GUARDIAN_CLI_APPROVERS: "
            "decisions will be refused until it is added.[/yellow]",
            highlight=False,
        )
    console.print("Press Ctrl+C to stop.")
    if not no_open:
        webbrowser.open(app.launch_url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        console.print("Stopped.")
    finally:
        server.server_close()

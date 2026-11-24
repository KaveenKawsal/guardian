"""``guardian doctor``: report which external tools and remediation prerequisites are ready."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from guardian.core.config import GuardianSettings, env_files
from guardian.core.exceptions import GuardianError
from guardian.execution.runner import ToolRunner
from guardian.integrations.jira.client import jira_client_from_settings
from guardian.llm.providers import mask_secret
from guardian.orchestration.checkpoint import checkpoint_path, open_checkpointer
from guardian.remediation.runtime import docker_sandbox

console = Console()

# tool -> (version args, purpose, install hint)
TOOLS: dict[str, tuple[tuple[str, ...], str, str]] = {
    "git": (("--version",), "Change analysis", "https://git-scm.com/downloads"),
    "cdxgen": (("--version",), "SBOM generation", "npm install -g @cyclonedx/cdxgen"),
    "osv-scanner": (
        ("--version",),
        "Vulnerability scanning",
        "winget install Google.OSVScanner (or https://google.github.io/osv-scanner/)",
    ),
    "semgrep": (("--version",), "Static analysis", "uv tool install semgrep"),
}

OK = "[green]ok[/green]"
WARN = "[yellow]warning[/yellow]"
FAIL = "[red]missing[/red]"


def doctor(
    online: Annotated[
        bool, typer.Option("--online", help="Also authenticate against Jira (network call).")
    ] = False,
) -> None:
    """Check external tools, Docker, Jira, LLM keys and Guardian's own storage."""
    runner = ToolRunner()
    table = Table(title="Guardian external tools", title_justify="left")
    table.add_column("Tool")
    table.add_column("Purpose")
    table.add_column("Status")
    table.add_column("Version / install")

    missing = 0
    for tool, (version_args, purpose, hint) in TOOLS.items():
        result = runner.run(tool, version_args, cwd=Path.cwd(), timeout_seconds=60)
        if result.ran:
            first_line = (result.stdout or result.stderr).strip().splitlines()
            table.add_row(
                tool, purpose, "[green]found[/green]", first_line[0] if first_line else ""
            )
        else:
            missing += 1
            table.add_row(tool, purpose, "[red]missing[/red]", hint)
    console.print(table)
    if missing:
        console.print(
            f"{missing} tool(s) missing. Guardian degrades gracefully and reports the "
            "analyses it could not run."
        )
    remediation_checks(online=online)


def remediation_checks(*, online: bool = False) -> None:
    """Prerequisites of the remediation workflow (sandbox, Jira, LLM, checkpoints)."""
    try:
        settings = GuardianSettings(_env_file=env_files())
    except ValueError as exc:
        console.print(f"[red]error:[/red] invalid configuration: {escape(str(exc))}")
        return
    table = Table(title="Remediation workflow", title_justify="left")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Detail", overflow="fold")
    for row in (
        _docker(settings),
        _jira(settings, online=online),
        _approvers(settings),
        *_llm_keys(settings),
        _checkpoints(settings),
    ):
        table.add_row(*row)
    console.print(table)


def _docker(settings: GuardianSettings) -> tuple[str, str, str]:
    sandbox = docker_sandbox(settings)
    ok, reason = sandbox.available()
    if not ok:
        return (
            "Docker sandbox",
            FAIL,
            escape(
                f"{reason}. Start Docker Desktop: without it lockfiles are not generated "
                "(partial dependency scan) and fixes end UNVERIFIED."
            ),
        )
    image = sandbox.config.base_image
    if not sandbox.image_exists(image):
        return ("Docker sandbox", WARN, escape(f"{reason}; run `docker pull {image}` first"))
    return ("Docker sandbox", OK, escape(f"{reason}; {image} present"))


def _jira(settings: GuardianSettings, *, online: bool) -> tuple[str, str, str]:
    if not settings.jira_configured:
        return (
            "Jira",
            WARN,
            (
                "not configured (JIRA_BASE_URL/EMAIL/API_TOKEN/PROJECT_KEY); use guardian decide "
                "or guardian ui"
            ),
        )
    target = f"{settings.jira_base_url} project {settings.jira_project_key}"
    if not online:
        return ("Jira", OK, escape(f"configured: {target} (--online to authenticate)"))
    try:
        with jira_client_from_settings(settings) as jira:
            me = jira.myself()
    except GuardianError as exc:
        return ("Jira", "[red]failed[/red]", escape(str(exc)))
    name = me.get("displayName") or me.get("emailAddress") or "?"
    return ("Jira", OK, escape(f"authenticated as {name}: {target}"))


def _approvers(settings: GuardianSettings) -> tuple[str, str, str]:
    detail = (
        f"CLI/UI: {', '.join(settings.cli_approvers) or 'none'}; "
        f"Jira accounts: {len(settings.approvers)}"
    )
    status = OK if settings.cli_approvers or settings.approvers else WARN
    if not settings.cli_approvers:
        detail += " (set GUARDIAN_CLI_APPROVERS to decide with guardian decide / guardian ui)"
    return ("Approvers", status, escape(detail))


def _llm_keys(settings: GuardianSettings) -> list[tuple[str, str, str]]:
    rows = []
    for name, key in (
        ("GROQ_API_KEY", settings.groq_api_key),
        ("GOOGLE_API_KEY", settings.google_api_key),
    ):
        status = OK if key is not None else WARN
        rows.append((name, status, escape(mask_secret(key))))
    return rows


def _checkpoints(settings: GuardianSettings) -> tuple[str, str, str]:
    path = checkpoint_path(settings.data_dir)
    try:
        with open_checkpointer(path):
            pass
    except Exception as exc:  # noqa: BLE001 - any failure means "not writable" here
        return ("Checkpoints", FAIL, escape(f"{path}: {exc}"))
    return ("Checkpoints", OK, escape(f"{path} writable"))

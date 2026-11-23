"""``guardian doctor``: report which external analysis tools are installed."""

from pathlib import Path

from rich.console import Console
from rich.table import Table

from guardian.execution.runner import ToolRunner

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


def doctor() -> None:
    """Check that the external analysis tools Guardian relies on are installed."""
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

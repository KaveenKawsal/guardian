"""``guardian scan``: profile a repository, generate its SBOM and build the dependency graph."""

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Annotated

import typer
from rich.markup import escape
from rich.table import Table

from guardian.cli.code import code_summary
from guardian.cli.common import cli_errors, console, err_console, open_database, styled_status
from guardian.cli.findings import findings_table, severity_summary
from guardian.cli.profile import render_profile
from guardian.core.config import GuardianSettings
from guardian.core.models import (
    DirectSource,
    Ecosystem,
    ManifestKind,
    RepositoryProfile,
    Severity,
)
from guardian.execution.policies import ExecutionPolicy
from guardian.execution.runner import ToolRunner
from guardian.orchestration.pipeline import ScanOutcome, ScanPipeline
from guardian.sources import (
    InvalidTargetError,
    RemoteTarget,
    Target,
    clone,
    parse_target,
    remove_workspace,
)

MAX_DIRECT_ROWS = 30
MAX_FINDING_ROWS = 15


def scan(
    target: Annotated[
        str | None,
        typer.Argument(
            help="Local path or repository URL (https://host/owner/repo, github.com/owner/repo, "
            "owner/repo). Prompted for when omitted in a terminal.",
            show_default=False,
        ),
    ] = None,
    ref: Annotated[
        str | None, typer.Option("--ref", help="Branch or tag to clone (remote targets only).")
    ] = None,
    keep: Annotated[
        bool,
        typer.Option(
            "--keep/--no-keep",
            help="Keep the clone of a remote repository after the scan (needed by "
            "'guardian explain' and 'guardian code').",
        ),
    ] = True,
    json_output: Annotated[
        bool, typer.Option("--json", help="Print the scan result as JSON.")
    ] = False,
) -> None:
    """Scan a repository: profile, SBOM, vulnerabilities, code and change analysis."""
    # Progress goes to stderr in JSON mode so stdout stays a single JSON document.
    progress = err_console if json_output else console
    settings = GuardianSettings()
    with cli_errors():
        source = resolve_target(target, ref)
        clone_dir: Path | None = None
        if isinstance(source, RemoteTarget):
            progress.print(f"Cloning [bold]{escape(source.display)}[/bold] ...")
            clone_dir = clone(source, settings, _clone_runner(settings))
            path = clone_dir
        else:
            path = source.path
        try:
            with open_database(settings) as db:
                progress.print(f"Scanning [bold]{escape(str(path.resolve()))}[/bold] ...")
                outcome = ScanPipeline(db, settings).run(path)
        finally:
            if clone_dir is not None and not keep:
                remove_workspace(clone_dir, settings)

    if json_output:
        payload = {
            "scan": outcome.record.model_dump(mode="json"),
            "profile": outcome.profile.model_dump(mode="json"),
            "sbom": outcome.sbom.model_dump(mode="json") if outcome.sbom else None,
            "findings": [f.model_dump(mode="json") for f in outcome.findings],
            "changes": [c.model_dump(mode="json") for c in outcome.changes],
            "code": code_summary(outcome.code_index) if outcome.code_index else None,
        }
        typer.echo(json.dumps(payload, indent=2))
    else:
        render_scan(outcome)
    for hint in lockfile_hints(outcome.profile):
        progress.print(f"[yellow]hint:[/yellow] {escape(hint)}")
    if clone_dir is not None:
        where = f"Clone kept at {clone_dir}" if keep else "Clone deleted (--no-keep)"
        progress.print(escape(where))


def resolve_target(target: str | None, ref: str | None) -> Target:
    """Parse the TARGET argument, prompting for it in an interactive terminal."""
    if target is None:
        if _stdin_is_tty():
            target = typer.prompt("Paste a GitHub URL or a local path to scan")
        else:
            target = "."  # scripts and pipes keep scanning the current directory
    source = parse_target(target)
    if isinstance(source, RemoteTarget):
        return source.with_ref(ref)
    if ref is not None:
        msg = "--ref only applies to remote repositories"
        raise InvalidTargetError(msg)
    return source


def _stdin_is_tty() -> bool:
    return sys.stdin.isatty()


def _clone_runner(settings: GuardianSettings) -> ToolRunner:
    return ToolRunner(
        ExecutionPolicy(
            timeout_seconds=settings.tool_timeout_seconds,
            max_output_bytes=settings.max_tool_output_bytes,
        )
    )


_LOCK_COMMANDS = {
    Ecosystem.NODE: "npm install --package-lock-only --ignore-scripts",
    Ecosystem.PYTHON: "uv lock (or poetry lock / pipenv lock)",
}


def lockfile_hints(profile: RepositoryProfile) -> list[str]:
    """Suggest generating a lockfile when JS/Python manifests have none (shallow graph)."""
    hints = []
    for eco in profile.ecosystems:
        command = _LOCK_COMMANDS.get(eco.ecosystem)
        manifests = [m for m in eco.manifests if m.kind is ManifestKind.MANIFEST]
        if command is None or not manifests or eco.lockfiles:
            continue
        if eco.ecosystem is Ecosystem.PYTHON and all(
            Path(m.path).name.startswith("requirements") for m in manifests
        ):
            continue  # requirements files usually pin versions already
        hints.append(
            f"No {eco.ecosystem.value} lockfile found, so transitive dependencies are "
            f"incomplete. Generate one in the repository with `{command}` and rescan; "
            "Guardian never runs package managers itself."
        )
    return hints


def render_scan(outcome: ScanOutcome) -> None:
    render_profile(outcome.profile, show_warnings=False)
    record, sbom = outcome.record, outcome.sbom

    if sbom is not None:
        by_ecosystem = Counter(
            c.ecosystem.value if c.ecosystem else (c.purl_type or "other") for c in sbom.components
        )
        console.rule("[bold]Dependencies")
        console.print(
            f"{len(sbom.components)} components "
            f"({', '.join(f'{n} {e}' for e, n in by_ecosystem.most_common())}), "
            f"{len(sbom.direct_components)} direct, {len(sbom.edges)} dependency edges"
        )
        if sbom.direct_source is DirectSource.GRAPH_INFERENCE:
            console.print("[yellow]Direct dependencies were inferred from the graph.[/yellow]")
        direct = outcome.graph.direct_dependencies()
        if direct:
            table = Table(title="Direct dependencies", title_justify="left")
            table.add_column("Package")
            table.add_column("Ecosystem")
            table.add_column("Scope")
            table.add_column("Transitive deps", justify="right")
            table.add_column("Vulns (own + via deps)", justify="right")
            graph = outcome.graph
            for component in direct[:MAX_DIRECT_ROWS]:
                transitive = graph.transitive_dependencies(component.ref)
                own = len(graph.findings_for_component(component.ref))
                inherited = sum(len(graph.findings_for_component(t.ref)) for t in transitive)
                table.add_row(
                    escape(component.display_name),
                    component.ecosystem.value if component.ecosystem else "-",
                    component.scope.value,
                    str(len(transitive)),
                    f"{own} + {inherited}" if own or inherited else "-",
                )
            console.print(table)
            if len(direct) > MAX_DIRECT_ROWS:
                console.print(f"... and {len(direct) - MAX_DIRECT_ROWS} more (guardian deps)")

    _render_code(outcome)

    console.rule("[bold]Security findings")
    visible = [f for f in outcome.findings if f.severity.rank >= Severity.LOW.rank]
    hidden = len(outcome.findings) - len(visible)
    if visible:
        console.print(findings_table(visible[:MAX_FINDING_ROWS], "Most severe findings"))
    console.print(
        f"{len(visible)} findings: {severity_summary(visible)}"
        + (f" (+{hidden} informational)" if hidden else "")
    )
    if len(visible) > MAX_FINDING_ROWS:
        console.print("All findings: [bold]guardian findings[/bold]")
    if visible:
        console.print("Details: [bold]guardian explain <ID>[/bold]")

    console.rule("[bold]Scan")
    for run in record.tool_runs:
        detail = f" - {escape(run.error)}" if run.error else ""
        console.print(f"{run.tool}: {styled_status(run.status)}{detail}")
    for warning in record.warnings:
        console.print(f"[yellow]warning:[/yellow] {escape(warning)}")
    console.print(f"Scan [bold]{record.id[:12]}[/bold] {styled_status(record.status.value)}")


def _render_code(outcome: ScanOutcome) -> None:
    index = outcome.code_index
    if index is None:
        return
    summary = code_summary(index)
    console.rule("[bold]Code")
    skipped = sum(summary["skipped_files"].values())
    console.print(
        f"{summary['files']} files indexed, {summary['symbols']} symbols, "
        f"{summary['entry_points']} entry points, "
        f"{len(summary['external_packages'])} external packages imported"
        + (f", {skipped} files skipped" if skipped else "")
    )
    console.print("Details: [bold]guardian code[/bold]")

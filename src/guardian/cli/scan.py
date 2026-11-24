"""``guardian scan``: profile a repository, generate its SBOM and build the dependency graph."""

import json
import sys
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from guardian.cli.code import code_summary
from guardian.cli.common import cli_errors, console, err_console, open_database, styled_status
from guardian.cli.findings import findings_table, severity_summary
from guardian.cli.profile import render_profile
from guardian.cli.report import DEFAULT_OUTPUT, generate_reports, parse_formats, print_written
from guardian.core.config import GuardianSettings
from guardian.core.exceptions import GuardianError
from guardian.core.models import (
    DirectSource,
    Ecosystem,
    ManifestKind,
    RepositoryProfile,
    ScanStatus,
    Severity,
    ToolRunSummary,
)
from guardian.execution.policies import ExecutionPolicy
from guardian.execution.results import ToolStatus
from guardian.execution.runner import ToolRunner
from guardian.orchestration.pipeline import (
    NPM_LOCKFILE,
    LockfileGenerator,
    ScanOutcome,
    ScanPipeline,
)
from guardian.remediation.runtime import docker_sandbox, lockfile_generator_for
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


def scan(  # noqa: PLR0913, PLR0917 - one parameter per CLI option
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
    write_report: Annotated[
        bool,
        typer.Option(
            "--report",
            help=f"After the scan, write review reports to ./{DEFAULT_OUTPUT} "
            "(HTML unless --report-format is given).",
        ),
    ] = False,
    report_formats: Annotated[
        list[str] | None,
        typer.Option(
            "--report-format",
            help="Report format for --report: html, md or json; repeatable or a comma list. "
            "Implies --report.",
            show_default=False,
        ),
    ] = None,
) -> None:
    """Scan a repository: profile, SBOM, vulnerabilities, code and change analysis."""
    # Progress goes to stderr in JSON mode so stdout stays a single JSON document.
    progress = err_console if json_output else console
    settings = GuardianSettings()
    formats = parse_formats(report_formats) if write_report or report_formats else None
    report_paths: list[Path] = []
    report_error: GuardianError | None = None
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
                generator = npm_lockfile_generator(path, settings, progress)
                outcome = ScanPipeline(db, settings, lockfile_generator=generator).run(path)
                if formats and outcome.record.status is not ScanStatus.FAILED:
                    # Before a --no-keep clone is deleted, so code snippets are still readable.
                    try:
                        _, report_paths = generate_reports(
                            db, outcome.record.id, settings, formats, DEFAULT_OUTPUT
                        )
                    except GuardianError as exc:
                        report_error = exc
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
    for hint in lockfile_hints(outcome.profile, outcome.record.tool_runs):
        progress.print(f"[yellow]hint:[/yellow] {escape(hint)}")
    if clone_dir is not None:
        where = f"Clone kept at {clone_dir}" if keep else "Clone deleted (--no-keep)"
        progress.print(escape(where))
    print_written(report_paths, progress)
    if report_error is not None:
        err_console.print(f"[red]error:[/red] report not written: {escape(str(report_error))}")
        raise typer.Exit(code=2)


NPM_LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")
DOCKER_DOWN_WARNING = (
    "{reason}: start Docker Desktop to generate a lockfile; dependency scan will be partial "
    "(package.json has no lockfile)."
)


def npm_lockfile_generator(
    path: Path, settings: GuardianSettings, progress: Console
) -> LockfileGenerator | None:
    """The Docker lockfile hook for an npm project without a lockfile (e.g. Juice Shop).

    None when generation is off, the project does not need it, or Docker is unavailable (then a
    warning explains why the dependency scan will be partial).
    """
    if not settings.npm_lockfile_generation:
        return None
    if not (path / "package.json").is_file() or any((path / n).exists() for n in NPM_LOCKFILES):
        return None
    sandbox = docker_sandbox(settings)
    ok, reason = sandbox.available()
    if not ok:
        warning = DOCKER_DOWN_WARNING.format(reason=reason)
        progress.print(f"[yellow]warning:[/yellow] {escape(warning)}")
        return None
    progress.print(
        "No npm lockfile: generating one in the Docker sandbox "
        "(npm install --package-lock-only --ignore-scripts); your repository is not modified."
    )
    return lockfile_generator_for(settings, sandbox)


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


def lockfile_hints(
    profile: RepositoryProfile, tool_runs: Sequence[ToolRunSummary] = ()
) -> list[str]:
    """Explain an incomplete dependency graph when JS/Python manifests have no lockfile."""
    npm_runs = [t for t in tool_runs if t.tool == NPM_LOCKFILE]
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
        if eco.ecosystem is Ecosystem.NODE:
            if npm_runs and npm_runs[-1].status == ToolStatus.SUCCESS.value:
                continue  # generated in the sandbox; the scan saw the full tree
            if npm_runs:
                hints.append(
                    "No npm lockfile, and generating one in the Docker sandbox failed (see the "
                    "npm-lockfile tool run / warning above), so transitive dependencies are "
                    "incomplete. Fix that error (is Docker Desktop running?) and rescan."
                )
            else:
                hints.append(
                    "No npm lockfile found, so transitive dependencies are incomplete. Start "
                    "Docker Desktop and rescan: Guardian generates one in its sandbox "
                    f"(`{command}`, nothing written to the repository; "
                    "GUARDIAN_NPM_LOCKFILE_GENERATION must be on)."
                )
            continue
        hints.append(
            f"No {eco.ecosystem.value} lockfile found, so transitive dependencies are "
            f"incomplete. Generate one in the repository with `{command}` and rescan; "
            "Guardian does not run this package manager itself."
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

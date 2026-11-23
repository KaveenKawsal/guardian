"""``guardian scan``: profile a repository, generate its SBOM and build the dependency graph."""

import json
from collections import Counter
from pathlib import Path
from typing import Annotated

import typer
from rich.markup import escape
from rich.table import Table

from guardian.cli.common import cli_errors, console, open_database, styled_status
from guardian.cli.findings import findings_table, severity_summary
from guardian.cli.profile import render_profile
from guardian.core.models import DirectSource, Severity
from guardian.orchestration.pipeline import ScanOutcome, ScanPipeline

MAX_DIRECT_ROWS = 30
MAX_FINDING_ROWS = 15


def scan(
    path: Annotated[Path, typer.Argument(help="Repository to scan.")] = Path(),
    json_output: Annotated[
        bool, typer.Option("--json", help="Print the scan result as JSON.")
    ] = False,
) -> None:
    """Scan a repository: profile, SBOM, vulnerabilities, code and change analysis."""
    with cli_errors(), open_database() as db:
        if not json_output:
            console.print(f"Scanning [bold]{escape(str(path.resolve()))}[/bold] ...")
        outcome = ScanPipeline(db).run(path)

    if json_output:
        payload = {
            "scan": outcome.record.model_dump(mode="json"),
            "profile": outcome.profile.model_dump(mode="json"),
            "sbom": outcome.sbom.model_dump(mode="json") if outcome.sbom else None,
            "findings": [f.model_dump(mode="json") for f in outcome.findings],
            "changes": [c.model_dump(mode="json") for c in outcome.changes],
        }
        typer.echo(json.dumps(payload, indent=2))
        return
    render_scan(outcome)


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

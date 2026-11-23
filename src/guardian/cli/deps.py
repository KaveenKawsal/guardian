"""``guardian deps``: explore a scan's dependency graph."""

import json
from typing import Annotated

import typer
from rich.markup import escape
from rich.table import Table

from guardian.cli.common import cli_errors, console, err_console, open_database
from guardian.knowledge.graph_builder import build_dependency_graph
from guardian.knowledge.graph_queries import DependencyGraph


def deps(
    scan_id: Annotated[
        str, typer.Argument(help="Scan id, unique id prefix, or 'latest'.")
    ] = "latest",
    why: Annotated[
        str | None,
        typer.Option("--why", help="Show how a package entered the dependency tree."),
    ] = None,
    show_all: Annotated[
        bool, typer.Option("--all", help="List every component, not only direct ones.")
    ] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Print JSON.")] = False,
) -> None:
    """List dependencies of a scan, or explain why a package is present (--why)."""
    with cli_errors(), open_database() as db:
        resolved = db.scans.resolve(scan_id)
        record = db.scans.get(resolved)
        profile = db.scans.profile(resolved)
        sbom = db.sboms.load(resolved)

    if sbom is None:
        err_console.print(f"Scan {record.id[:12]} has no SBOM (status: {record.status.value}).")
        raise typer.Exit(code=1)
    graph = DependencyGraph(build_dependency_graph(profile, sbom))

    if why is not None:
        _explain(graph, why, json_output=json_output)
        return

    components = graph.components() if show_all else graph.direct_dependencies()
    if json_output:
        typer.echo(json.dumps([c.model_dump(mode="json") for c in components], indent=2))
        return
    title = "All components" if show_all else "Direct dependencies"
    table = Table(title=f"{title} - {escape(record.repository_name)} @ {record.id[:12]}")
    table.add_column("Package")
    table.add_column("Ecosystem")
    table.add_column("Depth", justify="right")
    table.add_column("Licenses")
    table.add_column("Declared in")
    depths = graph.depths()  # one traversal instead of one per component
    for c in components:
        depth = depths.get(c.ref)
        table.add_row(
            escape(c.display_name),
            escape(c.ecosystem.value if c.ecosystem else (c.purl_type or "-")),
            str(depth) if depth is not None else "?",
            escape(", ".join(c.licenses) or "-"),
            escape(", ".join(c.declared_in) or "-"),
        )
    console.print(table)


def _explain(graph: DependencyGraph, name: str, *, json_output: bool) -> None:
    matches = graph.find(name)
    if not matches:
        err_console.print(f"No component named {name!r} in this scan.", markup=False)
        raise typer.Exit(code=1)

    results = [(c, graph.introduction_paths(c.ref)) for c in matches]
    if json_output:
        payload = [
            {
                "component": c.model_dump(mode="json"),
                "paths": [[p.display_name for p in path] for path in paths],
            }
            for c, paths in results
        ]
        typer.echo(json.dumps(payload, indent=2))
        return

    for component, paths in results:
        console.rule(f"[bold]{escape(component.display_name)}")
        if not paths:
            console.print("Not reachable from the repository in the dependency graph.")
            continue
        kind = "direct dependency" if len(paths[0]) == 1 else "transitive dependency"
        console.print(f"{component.display_name} is a {kind}. Introduced via:", markup=False)
        for path in paths:
            console.print("  " + " -> ".join(c.display_name for c in path), markup=False)

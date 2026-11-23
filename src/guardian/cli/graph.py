"""``guardian graph``: export a scan's dependency graph as an interactive HTML page."""

from pathlib import Path
from typing import Annotated

import typer

from guardian.cli.common import cli_errors, console, err_console, open_database
from guardian.reporting.graph_export import graph_payload, write_graph_page


def graph(
    scan_id: Annotated[str, typer.Argument(help="Scan id, unique prefix, or 'latest'.")] = "latest",
    output: Annotated[
        Path, typer.Option("--output", "-o", help="Directory to write index.html and graph.json.")
    ] = Path("guardian-graph"),
    embed: Annotated[
        bool,
        typer.Option(
            "--embed/--no-embed",
            help="Embed the data in index.html so it opens from disk (default), or fetch "
            "graph.json beside it, for hosting.",
        ),
    ] = True,
) -> None:
    """Write an interactive dependency graph: vulnerable paths, search, package inspector."""
    with cli_errors(), open_database() as db:
        resolved = db.scans.resolve(scan_id)
        record = db.scans.get(resolved)
        profile = db.scans.profile(resolved)
        sbom = db.sboms.load(resolved)
        findings = db.findings.load(resolved)

    if sbom is None:
        err_console.print(f"Scan {record.id[:12]} has no SBOM, so there is no dependency graph.")
        raise typer.Exit(code=1)
    payload = graph_payload(record, profile, sbom, findings)
    page = write_graph_page(payload, output, embed_data=embed)
    meta = payload["meta"]
    console.print(
        f"Wrote {page} ({meta['components']:,} packages, {meta['edges']:,} edges, "
        f"{len(payload['findings'])} known vulnerabilities)"
    )

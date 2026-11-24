"""``guardian compare``: before/after view of two scans (SBOM, findings, risk)."""

import json
from typing import Annotated

import typer
from rich.markup import escape
from rich.table import Table

from guardian.cli.common import cli_errors, console, open_database
from guardian.reporting.compare import ComparedFinding, ScanComparison, ScanRisk, compare_scans

MAX_ROWS = 50
_STATUS_STYLES = {
    "improved": "green",
    "regressed": "red",
    "mixed": "yellow",
    "unchanged": "dim",
}


def compare(
    scan_a: Annotated[
        str,
        typer.Argument(help="Earlier scan: id, unique prefix, or 'latest'.", show_default=False),
    ],
    scan_b: Annotated[
        str, typer.Argument(help="Later scan: id, unique prefix, or 'latest'.")
    ] = "latest",
    json_output: Annotated[bool, typer.Option("--json", help="Print JSON.")] = False,
) -> None:
    """Compare two scans: SBOM changes, findings resolved/still present/new, and risk."""
    with cli_errors(), open_database() as db:
        before = db.scans.resolve(scan_a)
        after = db.scans.resolve(scan_b)
        result = compare_scans(db, before, after)
    if json_output:
        typer.echo(json.dumps(result.model_dump(mode="json"), indent=2, ensure_ascii=False))
        return
    print_comparison(result)


def _score(value: float | None) -> str:
    return "-" if value is None else f"{value:.0f}"


def _risk_line(label: str, risk: ScanRisk) -> str:
    scan = risk.scan
    return (
        f"{label} [bold]{escape(scan.id[:12])}[/bold] {escape(scan.repository_name)} "
        f"({scan.started_at:%Y-%m-%d %H:%M} UTC, {scan.status.value}): "
        f"{risk.findings} findings, {risk.components} components, "
        f"max risk {_score(risk.max_score)}, total risk {risk.total_score:.0f}"
    )


def print_comparison(result: ScanComparison) -> None:
    style = _STATUS_STYLES[result.status]
    console.print(_risk_line("Before", result.before), soft_wrap=True)
    console.print(_risk_line("After ", result.after), soft_wrap=True)
    delta = result.after.total_score - result.before.total_score
    console.print(
        f"Status: [{style}]{result.status}[/{style}] · "
        f"{len(result.resolved)} resolved, {len(result.still_present)} still present, "
        f"{len(result.new)} new · max risk {_score(result.before.max_score)} -> "
        f"{_score(result.after.max_score)} · total risk {delta:+.0f}",
        soft_wrap=True,
    )
    _sbom_table(result)
    for title, rows in (
        ("Resolved findings", result.resolved),
        ("New findings", result.new),
        ("Still present", result.still_present),
    ):
        _findings_table(title, rows)


def _sbom_table(result: ScanComparison) -> None:
    diff = result.sbom_diff
    if not (diff.added or diff.removed or diff.changed):
        console.print("SBOM: no component changes.")
        return
    table = Table(title="SBOM changes", title_justify="left")
    for column in ("Change", "Component", "From", "To"):
        table.add_column(column)
    for change in diff.changed:
        table.add_row(
            "changed",
            escape(change.purl_base),
            escape(change.from_version or "-"),
            escape(change.to_version or "-"),
        )
    for purl in diff.added:
        table.add_row("[red]added[/red]", escape(purl), "-", "-")
    for purl in diff.removed:
        table.add_row("[green]removed[/green]", escape(purl), "-", "-")
    console.print(table)


def _findings_table(title: str, rows: list[ComparedFinding]) -> None:
    if not rows:
        return
    table = Table(title=f"{title} ({len(rows)})", title_justify="left")
    for column in ("Finding", "Severity", "Priority", "Risk", "Title"):
        table.add_column(column)
    for row in rows[:MAX_ROWS]:
        table.add_row(
            escape(row.id[:12]),
            row.severity.value,
            row.priority.value,
            _score(row.score),
            escape(row.title),
        )
    if len(rows) > MAX_ROWS:
        table.caption = f"{len(rows) - MAX_ROWS} more not shown; use --json for all."
    console.print(table)

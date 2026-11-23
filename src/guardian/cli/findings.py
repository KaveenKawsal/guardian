"""``guardian findings`` and ``guardian explain``: inspect security findings of a scan."""

import json
from collections import Counter
from typing import Annotated

import typer
from rich.markup import escape
from rich.table import Table

from guardian.cli.common import cli_errors, console, open_database
from guardian.core.models import (
    ChangeDetails,
    CodeDetails,
    Finding,
    FindingKind,
    Severity,
    VulnerabilityDetails,
)
from guardian.knowledge.graph_builder import build_knowledge_graph
from guardian.knowledge.graph_queries import DependencyGraph

SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.UNKNOWN: "magenta",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def styled_severity(severity: Severity) -> str:
    style = SEVERITY_STYLES[severity]
    return f"[{style}]{severity.value}[/{style}]"


def severity_summary(findings: list[Finding]) -> str:
    counts = Counter(f.severity for f in findings)
    ordered = sorted(counts, key=lambda s: -s.rank)
    return ", ".join(f"{counts[s]} {styled_severity(s)}" for s in ordered) or "none"


def findings_table(findings: list[Finding], title: str) -> Table:
    table = Table(title=title, title_justify="left")
    table.add_column("ID")
    table.add_column("Severity")
    table.add_column("Kind")
    table.add_column("Finding", overflow="fold")
    table.add_column("Where", overflow="fold")
    for f in findings:
        package = f.details.package if isinstance(f.details, VulnerabilityDetails) else None
        where = f.location or package
        table.add_row(
            f.id[:10],
            styled_severity(f.severity),
            f.kind.value,
            escape(f.title),
            escape(where or "-"),
        )
    return table


def findings(
    scan_id: Annotated[str, typer.Argument(help="Scan id, unique prefix, or 'latest'.")] = "latest",
    min_severity: Annotated[
        Severity, typer.Option("--min-severity", "-s", help="Hide less severe findings.")
    ] = Severity.LOW,
    kind: Annotated[
        FindingKind | None, typer.Option("--kind", "-k", help="Only this kind.")
    ] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Print JSON.")] = False,
) -> None:
    """List security findings of a scan, most severe first."""
    with cli_errors(), open_database() as db:
        resolved = db.scans.resolve(scan_id)
        record = db.scans.get(resolved)
        rows = db.findings.load(resolved, min_severity=min_severity, kind=kind)

    if json_output:
        typer.echo(json.dumps([f.model_dump(mode="json") for f in rows], indent=2))
        return
    if not rows:
        console.print(f"No findings at or above {min_severity.value} in scan {record.id[:12]}.")
        return
    title = f"Findings - {escape(record.repository_name)} @ {record.id[:12]}"
    console.print(findings_table(rows, title))
    console.print(f"{len(rows)} findings: {severity_summary(rows)}")
    console.print("Details: [bold]guardian explain <ID>[/bold]")


def explain(
    finding_id: Annotated[str, typer.Argument(help="Finding id or unique prefix.")],
    scan_id: Annotated[str, typer.Option("--scan", help="Scan id or 'latest'.")] = "latest",
    json_output: Annotated[bool, typer.Option("--json", help="Print JSON.")] = False,
) -> None:
    """Explain a finding: the facts, the evidence chain and remediation."""
    with cli_errors(), open_database() as db:
        resolved = db.scans.resolve(scan_id)
        finding = db.findings.get(resolved, finding_id)
        profile = db.scans.profile(resolved)
        sbom = db.sboms.load(resolved)
        changes = db.findings.changes(resolved)
        seen_in = db.findings.scans_containing(finding.id)
    graph = DependencyGraph(build_knowledge_graph(profile, sbom, [finding], changes))

    paths = []
    if finding.component_ref:
        paths = [
            [c.display_name for c in p] for p in graph.introduction_paths(finding.component_ref)
        ]
    if json_output:
        payload = {
            "finding": finding.model_dump(mode="json"),
            "introduction_paths": paths,
            "reported_in_scans": len(seen_in),
        }
        typer.echo(json.dumps(payload, indent=2))
        return

    console.rule(f"[bold]{escape(finding.title)}")
    console.print(
        f"ID: {finding.id}    Severity: {styled_severity(finding.severity)}    "
        f"Kind: {finding.kind.value}    Tool: {escape(finding.tool)}"
    )
    details = finding.details
    if isinstance(details, VulnerabilityDetails):
        _explain_vulnerability(details, paths)
    elif isinstance(details, CodeDetails):
        _explain_code(finding, details)
    elif isinstance(details, ChangeDetails):
        _explain_change(details)

    console.print("\n[bold]Evidence[/bold]")
    for item in finding.evidence:
        where = f" ({item.path}{f':{item.line}' if item.line else ''})" if item.path else ""
        link = f" {item.url}" if item.url else ""
        console.print(f"  - [{item.kind.value}] {item.summary}{where}{link}", markup=False)
    if len(seen_in) > 1:
        console.print(f"\nReported in {len(seen_in)} scans of this repository (still unresolved).")
    console.print(
        "\n[dim]Facts above come from deterministic tools. AI investigation of relevance "
        "and exploitability arrives in phase 5.[/dim]"
    )


def _explain_vulnerability(d: VulnerabilityDetails, paths: list[list[str]]) -> None:
    if d.summary:
        console.print(f"Summary: {d.summary}", markup=False)
    console.print(f"Package: {d.package}@{d.version} ({d.ecosystem})", markup=False)
    if d.aliases:
        console.print(f"Also known as: {', '.join(d.aliases)}", markup=False)
    if d.cvss_score is not None:
        console.print(f"CVSS: {d.cvss_score}")
    if d.cwe_ids:
        console.print(f"Weakness: {', '.join(d.cwe_ids)}", markup=False)
    if paths:
        console.print("\n[bold]How it enters the application[/bold]")
        kind = "direct dependency" if len(paths[0]) == 1 else "transitive dependency"
        console.print(f"  {d.package} is a {kind}:", markup=False)
        for path in paths:
            console.print("    " + " -> ".join(path), markup=False)
    console.print("\n[bold]Remediation[/bold]")
    if d.recommended_fix:
        console.print(f"  Upgrade {d.package} to {d.recommended_fix} or later.", markup=False)
        if paths and len(paths[0]) > 1:
            console.print(
                f"  It is transitive: upgrade {paths[0][0]} to a release that depends on a fixed "
                f"{d.package}, or pin/override {d.package}.",
                markup=False,
            )
    elif d.fixed_versions:
        console.print(f"  Fixed in: {', '.join(d.fixed_versions)}", markup=False)
    else:
        console.print(
            "  No fixed version is published; consider replacing or isolating the package."
        )


def _explain_code(finding: Finding, d: CodeDetails) -> None:
    console.print(f"Location: {finding.location}", markup=False)
    if finding.symbol_id:
        console.print(f"Symbol: {finding.symbol_id}", markup=False)
    console.print(f"Rule: {d.rule_id}", markup=False)
    if d.cwe_ids:
        console.print(f"Weakness: {', '.join(d.cwe_ids)}", markup=False)
    rated = (("confidence", d.confidence), ("likelihood", d.likelihood), ("impact", d.impact))
    meta = [f"{k}={v}" for k, v in rated if v]
    if meta:
        console.print("Rule metadata: " + ", ".join(meta), markup=False)
    console.print(f"\n{d.message}", markup=False)
    for ref in d.references:
        console.print(f"  {ref}", markup=False)


def _explain_change(d: ChangeDetails) -> None:
    console.print(f"Category: {d.category.value}")
    if d.commit:
        when = d.authored_at.date().isoformat() if d.authored_at else "unknown date"
        console.print(f"Commit: {d.commit} by {d.author or 'unknown'} on {when}", markup=False)
        if d.subject:
            console.print(f"Message: {d.subject}", markup=False)
    console.print("Files: " + ", ".join(d.paths), markup=False)

"""Export a scan's dependency graph as a self-contained interactive HTML page.

Everything in the payload (package names, advisory summaries, repository names) originates
from the scanned repository or third-party feeds, so it is treated as untrusted: the JSON is
escaped for embedding in ``<script>``, the title is HTML-escaped, and the page renders all
data with ``textContent`` only.
"""

import html
import json
from importlib.resources import files
from pathlib import Path
from typing import Any

from guardian.core.models import (
    EvidenceKind,
    Finding,
    FindingKind,
    RepositoryProfile,
    Sbom,
    ScanRecord,
    VulnerabilityDetails,
)
from guardian.knowledge.graph_builder import build_knowledge_graph
from guardian.knowledge.graph_queries import DependencyGraph

DATA_PLACEHOLDER = "/*__GRAPH_DATA__*/"
TITLE_PLACEHOLDER = "__TITLE__"


def graph_payload(
    record: ScanRecord, profile: RepositoryProfile, sbom: Sbom, findings: list[Finding]
) -> dict[str, Any]:
    vuln_findings = [f for f in findings if f.kind is FindingKind.VULNERABILITY and f.component_ref]
    graph = DependencyGraph(build_knowledge_graph(profile, sbom, vuln_findings, []))
    components = graph.components()
    index = {c.ref: i + 1 for i, c in enumerate(components)}  # 0 is the repository
    depths = graph.depths()

    finding_rows: list[dict[str, Any]] = []
    by_component: dict[str, list[int]] = {}
    for finding in vuln_findings:
        details = finding.details
        if not isinstance(details, VulnerabilityDetails) or finding.component_ref not in index:
            continue
        advisory = next((e.url for e in finding.evidence if e.kind is EvidenceKind.ADVISORY), None)
        by_component.setdefault(finding.component_ref, []).append(len(finding_rows))
        finding_rows.append(
            {
                "id": finding.id,
                "vulnerability_id": details.vulnerability_id,
                "severity": finding.severity.value,
                "summary": details.summary,
                "cvss": details.cvss_score,
                "fix": details.recommended_fix,
                "cwe": details.cwe_ids,
                "url": advisory,
            }
        )

    nodes: list[dict[str, Any]] = [{"name": profile.name, "root": True, "depth": 0}]
    for component in components:
        node: dict[str, Any] = {
            "name": f"{component.group}/{component.name}" if component.group else component.name,
            "version": component.version,
            "eco": component.ecosystem.value if component.ecosystem else component.purl_type,
            "depth": depths.get(component.ref),
            "scope": component.scope.value,
        }
        if component.licenses:
            node["licenses"] = component.licenses
        if component.declared_in:
            node["declared"] = component.declared_in
        if component.ref in by_component:
            node["f"] = by_component[component.ref]
        nodes.append(node)

    links = sorted(
        {
            (0 if edge.source == sbom.root_ref else index[edge.source], index[edge.target])
            for edge in sbom.edges
            if edge.target in index and (edge.source == sbom.root_ref or edge.source in index)
        }
    )
    return {
        "meta": {
            "title": f"{profile.name} dependency graph",
            "repository": profile.name,
            "scan_id": record.id,
            "scanned_at": record.started_at.isoformat(),
            "commit": record.git_commit,
            "components": len(components),
            "direct": sum(1 for d in depths.values() if d == 1),
            "edges": len(links),
        },
        "nodes": nodes,
        "links": [list(pair) for pair in links],
        "findings": finding_rows,
    }


def _script_safe_json(payload: dict[str, Any]) -> str:
    """JSON that cannot terminate the surrounding <script> element."""
    text = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    return text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def render_graph_html(payload: dict[str, Any], *, embed_data: bool = True) -> str:
    template = files("guardian.reporting").joinpath("templates", "dependency_graph.html")
    page = template.read_text("utf-8").replace(
        TITLE_PLACEHOLDER, html.escape(payload["meta"]["title"]), 1
    )
    if embed_data:
        page = page.replace(DATA_PLACEHOLDER, _script_safe_json(payload), 1)
    return page


def write_graph_page(payload: dict[str, Any], output_dir: Path, *, embed_data: bool = True) -> Path:
    """Write ``index.html`` (and ``graph.json``) into ``output_dir``; return the page path.

    With ``embed_data`` the page works opened straight from disk. Without it the page
    fetches ``graph.json`` from beside itself, which suits hosting.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "graph.json").write_text(
        json.dumps(payload, separators=(",", ":"), ensure_ascii=False), encoding="utf-8"
    )
    page = output_dir / "index.html"
    page.write_text(render_graph_html(payload, embed_data=embed_data), encoding="utf-8")
    return page

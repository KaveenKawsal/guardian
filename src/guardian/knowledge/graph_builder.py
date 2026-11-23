"""Build the dependency knowledge graph from a repository profile and its SBOM.

Nodes                                   Edges
  repository:<name>    (REPOSITORY)       repository -CONTAINS->    file
  file:<path>          (FILE)             repository -DEPENDS_ON->  component  (direct)
  component:<ref>      (COMPONENT)        component  -DEPENDS_ON->  component  (transitive)
                                          component  -DECLARED_IN-> file

Phase 4 extends the same graph with source files, symbols, imports and calls (see
``add_code_layer``).
"""

from collections.abc import Callable, Iterable
from typing import Any

import networkx as nx

from guardian.core.models import (
    ChangeRecord,
    CodeIndex,
    Finding,
    ImportTarget,
    NodeType,
    Relation,
    RepositoryProfile,
    ResolvedCall,
    ResolvedImport,
    Sbom,
    Symbol,
)

MAX_CALL_LINES = 20


def repository_node(name: str) -> str:
    return f"repository:{name}"


def file_node(path: str) -> str:
    return f"file:{path}"


def component_node(ref: str) -> str:
    return f"component:{ref}"


def build_dependency_graph(profile: RepositoryProfile, sbom: Sbom | None) -> nx.DiGraph:
    graph = nx.DiGraph()
    repo = repository_node(profile.name)
    graph.add_node(repo, type=NodeType.REPOSITORY, name=profile.name, root=profile.root)

    for ecosystem in profile.ecosystems:
        for manifest in ecosystem.manifests:
            node = file_node(manifest.path)
            graph.add_node(
                node,
                type=NodeType.FILE,
                path=manifest.path,
                kind=manifest.kind,
                ecosystem=manifest.ecosystem,
            )
            graph.add_edge(repo, node, relation=Relation.CONTAINS)

    if sbom is None:
        return graph

    for component in sbom.components:
        node = component_node(component.ref)
        graph.add_node(node, type=NodeType.COMPONENT, component=component)
        for path in component.declared_in:
            if graph.has_node(file_node(path)):
                graph.add_edge(node, file_node(path), relation=Relation.DECLARED_IN)

    for edge in sbom.edges:
        # The SBOM root component *is* the repository being scanned.
        source = repo if edge.source == sbom.root_ref else component_node(edge.source)
        target = component_node(edge.target)
        if graph.has_node(source) and graph.has_node(target):
            graph.add_edge(source, target, relation=Relation.DEPENDS_ON)
    return graph


def symbol_node(symbol_id: str) -> str:
    return f"symbol:{symbol_id}"


def finding_node(finding_id: str) -> str:
    return f"finding:{finding_id}"


def change_node(commit: str) -> str:
    return f"change:{commit}"


def _ensure_file(graph: nx.DiGraph, repo: str, path: str) -> str:
    node = file_node(path)
    if not graph.has_node(node):
        graph.add_node(node, type=NodeType.FILE, path=path, kind="source")
        graph.add_edge(repo, node, relation=Relation.CONTAINS)
    return node


def add_security_layer(
    graph: nx.DiGraph,
    profile: RepositoryProfile,
    findings: Iterable[Finding],
    changes: Iterable[ChangeRecord],
) -> nx.DiGraph:
    """Add findings and changes.

    component -AFFECTED_BY->   finding     (known vulnerability)
    file      -AFFECTED_BY->   finding     (code finding, change finding on one file)
    finding   -INTRODUCED_BY-> change      (commit that last touched the flagged lines)
    change    -MODIFIES->      file
    """
    repo = repository_node(profile.name)
    for change in changes:
        node = change_node(change.commit)
        graph.add_node(node, type=NodeType.CHANGE, change=change)
        for file_change in change.files:
            graph.add_edge(
                node,
                _ensure_file(graph, repo, file_change.path),
                relation=Relation.MODIFIES,
                status=file_change.status,
            )

    for finding in findings:
        node = finding_node(finding.id)
        graph.add_node(node, type=NodeType.FINDING, finding=finding)
        if finding.component_ref and graph.has_node(component_node(finding.component_ref)):
            graph.add_edge(
                component_node(finding.component_ref), node, relation=Relation.AFFECTED_BY
            )
        if finding.path:
            graph.add_edge(
                _ensure_file(graph, repo, finding.path), node, relation=Relation.AFFECTED_BY
            )
        if finding.introduced_by:
            commit = change_node(finding.introduced_by)
            if not graph.has_node(commit):
                graph.add_node(
                    commit, type=NodeType.CHANGE, change=ChangeRecord(commit=finding.introduced_by)
                )
            graph.add_edge(node, commit, relation=Relation.INTRODUCED_BY)
    return graph


def add_code_layer(graph: nx.DiGraph, profile: RepositoryProfile, index: CodeIndex) -> nx.DiGraph:
    """Add indexed source files, their symbols, imports and calls.

    file   -DEFINES-> symbol      (top-level)        symbol -DEFINES-> symbol (nested)
    file   -IMPORTS-> file        (INTERNAL import)  attrs: lines, modules (sorted lists)
    file   -IMPORTS-> component   (EXTERNAL import of a component in the graph)
    symbol -CALLS->   symbol      (the file is the caller for module-level calls)
    symbol -CALLS->   component   attrs: count, lines (first 20), members (sorted)

    The graph is a DiGraph, so a pair of nodes holds one edge. Repeated imports/calls between
    the same pair are merged into that edge. When the pair already has an edge with another
    relation (e.g. a module-level call to a function the file DEFINES) the existing edge is
    kept and the new one is skipped. Imports/calls into components that are not graph nodes
    (no SBOM entry) are skipped too.
    """
    repo = repository_node(profile.name)
    symbols: dict[str, Symbol] = {}
    for file in index.files:
        node = _ensure_file(graph, repo, file.path)
        graph.nodes[node].setdefault("language", file.language)
        symbols.update((s.id, s) for s in file.symbols)
    for symbol in symbols.values():
        graph.add_node(symbol_node(symbol.id), type=NodeType.SYMBOL, symbol=symbol)
    for symbol in symbols.values():
        parent = (
            symbol_node(symbol.parent_id)
            if symbol.parent_id is not None and symbol.parent_id in symbols
            else _ensure_file(graph, repo, symbol.path)
        )
        _add_or_merge(graph, (parent, symbol_node(symbol.id)), Relation.DEFINES)
    _add_imports(graph, repo, index.imports)
    _add_calls(graph, repo, index.calls, symbols)
    return graph


_Merge = Callable[[dict[str, Any], dict[str, Any]], None]


def _add_or_merge(
    graph: nx.DiGraph,
    edge: tuple[str, str],
    relation: Relation,
    *,
    attrs: dict[str, Any] | None = None,
    merge: _Merge | None = None,
) -> bool:
    """Add ``source -relation-> target``, or merge ``attrs`` into the existing edge of the
    same relation. Returns False (changing nothing) when the pair already has an edge with
    another relation."""
    source, target = edge
    attrs = attrs or {}
    if graph.has_edge(source, target):
        existing = graph.edges[source, target]
        if existing["relation"] is not relation:
            return False
        if merge is not None:
            merge(existing, attrs)
        return True
    graph.add_edge(source, target, relation=relation, **attrs)
    return True


def _merge_imports(existing: dict[str, Any], new: dict[str, Any]) -> None:
    existing["lines"] = sorted(set(existing.get("lines", [])) | set(new["lines"]))
    existing["modules"] = sorted(set(existing.get("modules", [])) | set(new["modules"]))


def _merge_calls(existing: dict[str, Any], new: dict[str, Any]) -> None:
    existing["count"] = existing.get("count", 0) + new["count"]
    lines = set(existing.get("lines", [])) | set(new["lines"])
    existing["lines"] = sorted(lines)[:MAX_CALL_LINES]
    existing["members"] = sorted(set(existing.get("members", [])) | set(new["members"]))


def _add_imports(graph: nx.DiGraph, repo: str, imports: Iterable[ResolvedImport]) -> None:
    grouped: dict[tuple[str, str], tuple[set[int], set[str]]] = {}
    for imp in imports:
        target = _import_target(graph, repo, imp)
        if target is None:
            continue
        source = _ensure_file(graph, repo, imp.path)
        lines, modules = grouped.setdefault((source, target), (set(), set()))
        lines.add(imp.line)
        modules.add(imp.module)
    for (source, target), (lines, modules) in grouped.items():
        attrs = {"lines": sorted(lines), "modules": sorted(modules)}
        _add_or_merge(graph, (source, target), Relation.IMPORTS, attrs=attrs, merge=_merge_imports)


def _import_target(graph: nx.DiGraph, repo: str, imp: ResolvedImport) -> str | None:
    if imp.target is ImportTarget.INTERNAL and imp.target_path:
        return _ensure_file(graph, repo, imp.target_path)
    if imp.target is ImportTarget.EXTERNAL and imp.component_ref:
        node = component_node(imp.component_ref)
        if graph.has_node(node):
            return node
    return None


def _add_calls(
    graph: nx.DiGraph, repo: str, calls: Iterable[ResolvedCall], symbols: dict[str, Symbol]
) -> None:
    grouped: dict[tuple[str, str], tuple[list[int], set[str]]] = {}
    for call in calls:
        target = _call_target(graph, call, symbols)
        if target is None:
            continue
        if call.caller_id is not None and call.caller_id in symbols:
            source = symbol_node(call.caller_id)
        else:
            source = _ensure_file(graph, repo, call.path)
        lines, members = grouped.setdefault((source, target), ([], set()))
        lines.append(call.line)
        if call.member and graph.nodes[target]["type"] is NodeType.COMPONENT:
            members.add(call.member)
    for (source, target), (lines, members) in grouped.items():
        attrs = {
            "count": len(lines),
            "lines": sorted(set(lines))[:MAX_CALL_LINES],
            "members": sorted(members),
        }
        _add_or_merge(graph, (source, target), Relation.CALLS, attrs=attrs, merge=_merge_calls)


def _call_target(graph: nx.DiGraph, call: ResolvedCall, symbols: dict[str, Symbol]) -> str | None:
    if call.target_symbol_id is not None and call.target_symbol_id in symbols:
        return symbol_node(call.target_symbol_id)
    if call.component_ref and graph.has_node(component_node(call.component_ref)):
        return component_node(call.component_ref)
    return None


def build_knowledge_graph(
    profile: RepositoryProfile,
    sbom: Sbom | None,
    findings: Iterable[Finding] = (),
    changes: Iterable[ChangeRecord] = (),
    code_index: CodeIndex | None = None,
) -> nx.DiGraph:
    """Dependency + security layers, plus the code layer when ``code_index`` is given."""
    graph = add_security_layer(build_dependency_graph(profile, sbom), profile, findings, changes)
    if code_index is not None:
        add_code_layer(graph, profile, code_index)
    return graph

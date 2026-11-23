"""Build the dependency knowledge graph from a repository profile and its SBOM.

Nodes                                   Edges
  repository:<name>    (REPOSITORY)       repository -CONTAINS->    file
  file:<path>          (FILE)             repository -DEPENDS_ON->  component  (direct)
  component:<ref>      (COMPONENT)        component  -DEPENDS_ON->  component  (transitive)
                                          component  -DECLARED_IN-> file

Phase 4 extends the same graph with source files, symbols, imports and calls.
"""

from collections.abc import Iterable

import networkx as nx

from guardian.core.models import (
    ChangeRecord,
    Finding,
    NodeType,
    Relation,
    RepositoryProfile,
    Sbom,
)


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


def build_knowledge_graph(
    profile: RepositoryProfile,
    sbom: Sbom | None,
    findings: Iterable[Finding] = (),
    changes: Iterable[ChangeRecord] = (),
) -> nx.DiGraph:
    return add_security_layer(build_dependency_graph(profile, sbom), profile, findings, changes)

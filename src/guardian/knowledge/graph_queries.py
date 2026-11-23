"""Queries over the dependency knowledge graph.

These answer the Dependency Investigator's core questions: what does the repository depend
on, and through which chain of packages did a given component enter the application?
"""

from itertools import islice, takewhile

import networkx as nx

from guardian.adapters.base import normalize_package_name
from guardian.core.models import ChangeRecord, Component, Finding, NodeType, Relation, Symbol
from guardian.knowledge.graph_builder import component_node, finding_node, symbol_node


class DependencyGraph:
    def __init__(self, graph: nx.DiGraph) -> None:
        self.graph = graph
        roots = [n for n, d in graph.nodes(data=True) if d["type"] is NodeType.REPOSITORY]
        if len(roots) != 1:
            msg = f"Expected exactly one repository node, found {len(roots)}"
            raise ValueError(msg)
        self.root = roots[0]
        self._deps = nx.subgraph_view(
            graph,
            filter_edge=lambda u, v: graph.edges[u, v]["relation"] is Relation.DEPENDS_ON,
        )

    def component(self, node: str) -> Component:
        return self.graph.nodes[node]["component"]

    def components(self) -> list[Component]:
        return sorted(
            (d["component"] for _, d in self.graph.nodes(data=True) if "component" in d),
            key=lambda c: c.display_name.lower(),
        )

    def direct_dependencies(self) -> list[Component]:
        return sorted(
            (self.component(n) for n in self._deps.successors(self.root)),
            key=lambda c: c.display_name.lower(),
        )

    def find(self, name: str) -> list[Component]:
        """Components whose name (or ``group/name``) matches, ignoring case and separators."""
        wanted = normalize_package_name(name)
        return [
            c
            for c in self.components()
            if wanted
            in {
                normalize_package_name(c.name),
                normalize_package_name(f"{c.group}/{c.name}" if c.group else c.name),
            }
        ]

    def dependencies_of(self, ref: str) -> list[Component]:
        node = component_node(ref)
        return [self.component(n) for n in self._deps.successors(node)]

    def dependents_of(self, ref: str) -> list[Component]:
        """Components that depend directly on ``ref`` (excluding the repository itself)."""
        node = component_node(ref)
        return [self.component(n) for n in self._deps.predecessors(node) if n != self.root]

    def transitive_dependencies(self, ref: str) -> list[Component]:
        node = component_node(ref)
        return [self.component(n) for n in nx.descendants(self._deps, node)]

    def introduction_paths(
        self, ref: str, *, limit: int = 5, max_depth: int = 25
    ) -> list[list[Component]]:
        """Shortest dependency chains from the repository to ``ref``, shortest first.

        Each path starts with a direct dependency and ends with the component itself.
        """
        target = component_node(ref)
        if not self._deps.has_node(target) or not nx.has_path(self._deps, self.root, target):
            return []
        paths = nx.shortest_simple_paths(self._deps, self.root, target)
        # Paths arrive in length order, so stop at the first one that is too deep instead of
        # filtering (which would enumerate an exponential number of longer paths).
        bounded = takewhile(lambda p: len(p) - 1 <= max_depth, paths)
        return [[self.component(n) for n in path[1:]] for path in islice(bounded, limit)]

    def findings(self) -> list[Finding]:
        found = [d["finding"] for _, d in self.graph.nodes(data=True) if "finding" in d]
        return sorted(found, key=lambda f: (-f.severity.rank, f.title))

    def findings_for_component(self, ref: str) -> list[Finding]:
        node = component_node(ref)
        if not self.graph.has_node(node):
            return []
        return [
            self.graph.nodes[target]["finding"]
            for _, target, data in self.graph.out_edges(node, data=True)
            if data["relation"] is Relation.AFFECTED_BY
        ]

    def vulnerable_components(self) -> list[Component]:
        return [c for c in self.components() if self.findings_for_component(c.ref)]

    def introducing_change(self, finding_id: str) -> ChangeRecord | None:
        node = finding_node(finding_id)
        if not self.graph.has_node(node):
            return None
        for _, target, data in self.graph.out_edges(node, data=True):
            if data["relation"] is Relation.INTRODUCED_BY:
                return self.graph.nodes[target]["change"]
        return None

    def depths(self) -> dict[str, int]:
        """Shortest dependency depth of every reachable component (1 = direct)."""
        lengths = nx.single_source_shortest_path_length(self._deps, self.root)
        return {
            self.graph.nodes[n]["component"].ref: d
            for n, d in lengths.items()
            if n != self.root and "component" in self.graph.nodes[n]
        }

    def depth(self, ref: str) -> int | None:
        """1 for direct dependencies; None when unreachable from the repository."""
        try:
            return nx.shortest_path_length(self._deps, self.root, component_node(ref))
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

    # --- Code layer (phase 4) ------------------------------------------------------------
    #
    # Callers/callees are reported as symbol ids for symbol nodes and as graph node ids
    # (``file:<path>`` for module-level code, ``component:<ref>`` for packages) otherwise.

    def symbol(self, symbol_id: str) -> Symbol | None:
        data = self.graph.nodes.get(symbol_node(symbol_id))
        return data.get("symbol") if data else None

    def importers_of(self, component_ref: str) -> list[str]:
        """Repository-relative paths of the files that import the component."""
        return sorted(
            self.graph.nodes[n]["path"]
            for n in self._related(component_node(component_ref), Relation.IMPORTS, incoming=True)
        )

    def callers_into(self, component_ref: str) -> list[tuple[str, list[str]]]:
        """(caller, members called) for every symbol or file that calls into the component."""
        node = component_node(component_ref)
        if not self.graph.has_node(node):
            return []
        return sorted(
            (self._code_id(source), list(data.get("members", [])))
            for source, _, data in self.graph.in_edges(node, data=True)
            if data["relation"] is Relation.CALLS
        )

    def is_imported(self, component_ref: str) -> bool:
        """True when any file imports or calls into the component."""
        node = component_node(component_ref)
        return bool(
            self._related(node, Relation.IMPORTS, incoming=True)
            or self._related(node, Relation.CALLS, incoming=True)
        )

    def callers_of_symbol(self, symbol_id: str) -> list[str]:
        node = symbol_node(symbol_id)
        return sorted(self._code_id(n) for n in self._related(node, Relation.CALLS, incoming=True))

    def callees_of_symbol(self, symbol_id: str) -> list[str]:
        node = symbol_node(symbol_id)
        return sorted(self._code_id(n) for n in self._related(node, Relation.CALLS, incoming=False))

    def _related(self, node: str, relation: Relation, *, incoming: bool) -> list[str]:
        if not self.graph.has_node(node):
            return []
        edges = (
            self.graph.in_edges(node, data=True)
            if incoming
            else self.graph.out_edges(node, data=True)
        )
        return [
            (source if incoming else target)
            for source, target, data in edges
            if data["relation"] is relation
        ]

    def _code_id(self, node: str) -> str:
        symbol = self.graph.nodes[node].get("symbol")
        return symbol.id if symbol is not None else node

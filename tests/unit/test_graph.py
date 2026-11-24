import json
import os
from pathlib import Path

import pytest

from guardian.analysis.cyclonedx import parse_cyclonedx
from guardian.core.config import GuardianSettings
from guardian.core.models import NodeType, Relation
from guardian.core.profiler import RepositoryProfiler
from guardian.knowledge.graph_builder import (
    build_dependency_graph,
    component_node,
    file_node,
    repository_node,
)
from guardian.knowledge.graph_queries import DependencyGraph

FIXTURES = Path(__file__).parents[1] / "fixtures" / "sbom"


@pytest.fixture
def setup(make_repo):
    root = make_repo(
        {"package.json": '{"dependencies": {"express": "4"}}', "package-lock.json": "{}"}
    )
    profile = RepositoryProfiler(settings=GuardianSettings(_env_file=None)).profile(root)
    raw = (FIXTURES / "node-express.cdx.json").read_text()
    # Point SrcFile at this checkout so DECLARED_IN resolves. Replace the trailing separator
    # too, so the path uses this OS's separator (a stray backslash breaks it on POSIX).
    native_root = json.dumps(str(root) + os.sep)[1:-1]
    raw = raw.replace("C:\\\\Temp\\\\elsewhere\\\\sample\\\\", native_root)
    sbom = parse_cyclonedx(
        raw,
        repo_root=root,
        manifests=profile.manifest_paths,
        declared=profile.declared_dependencies,
    )
    return profile, sbom


@pytest.fixture
def graph(setup):
    profile, sbom = setup
    return DependencyGraph(build_dependency_graph(profile, sbom))


def test_structure(setup):
    profile, sbom = setup
    g = build_dependency_graph(profile, sbom)
    repo = repository_node("repo")
    assert g.nodes[repo]["type"] is NodeType.REPOSITORY
    assert g.edges[repo, file_node("package.json")]["relation"] is Relation.CONTAINS
    assert (
        g.edges[repo, component_node("pkg:npm/express@4.17.1")]["relation"] is Relation.DEPENDS_ON
    )
    declared = g.edges[component_node("pkg:npm/express@4.17.1"), file_node("package-lock.json")]
    assert declared["relation"] is Relation.DECLARED_IN


def test_profile_only_graph(setup):
    profile, _ = setup
    g = build_dependency_graph(profile, None)
    assert DependencyGraph(g).components() == []
    assert g.number_of_nodes() == 3  # repository + two manifests


def test_direct_and_depth(graph):
    assert [c.name for c in graph.direct_dependencies()] == ["express", "lodash"]
    assert graph.depth("pkg:npm/express@4.17.1") == 1
    assert graph.depth("pkg:npm/mime-types@2.1.35") == 3
    assert graph.depth("nested-ref") is None
    assert graph.depth("does-not-exist") is None


def test_introduction_paths(graph):
    paths = graph.introduction_paths("pkg:npm/mime-types@2.1.35")
    assert [[c.name for c in p] for p in paths] == [
        ["express", "accepts", "mime-types"],
        ["express", "type-is", "mime-types"],
    ]
    assert graph.introduction_paths("pkg:npm/mime-types@2.1.35", limit=1) == paths[:1]
    assert graph.introduction_paths("pkg:npm/mime-types@2.1.35", max_depth=2) == []
    assert graph.introduction_paths("nested-ref") == []
    assert graph.introduction_paths("missing") == []


def test_dependents_and_transitive(graph):
    assert sorted(c.name for c in graph.dependents_of("pkg:npm/mime-types@2.1.35")) == [
        "accepts",
        "type-is",
    ]
    assert graph.dependents_of("pkg:npm/express@4.17.1") == []  # repository excluded
    assert sorted(c.name for c in graph.transitive_dependencies("pkg:npm/express@4.17.1")) == [
        "accepts",
        "mime-types",
        "type-is",
    ]
    assert [c.name for c in graph.dependencies_of("pkg:npm/accepts@1.3.8")] == ["mime-types"]


def test_find(graph):
    assert [c.name for c in graph.find("Express")] == ["express"]
    assert [c.display_name for c in graph.find("@types/node")] == ["@types/node@20.0.0"]
    assert graph.find("nope") == []


def test_requires_single_repository_node():
    import networkx as nx

    with pytest.raises(ValueError, match="exactly one repository"):
        DependencyGraph(nx.DiGraph())

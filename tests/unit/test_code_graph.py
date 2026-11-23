import pytest

from guardian.core.config import GuardianSettings
from guardian.core.models import (
    CodeDetails,
    CodeIndex,
    Component,
    DependencyEdge,
    FileIndex,
    Finding,
    FindingKind,
    GitInfo,
    ImportStyle,
    ImportTarget,
    NodeType,
    Relation,
    RepositoryProfile,
    ResolvedCall,
    ResolvedImport,
    Sbom,
    Severity,
    SourceLanguage,
    Span,
    Symbol,
    SymbolKind,
)
from guardian.core.profiler import RepositoryProfiler
from guardian.indexing.repository_indexer import RepositoryIndexer
from guardian.knowledge.graph_builder import (
    add_code_layer,
    build_dependency_graph,
    build_knowledge_graph,
    component_node,
    file_node,
    repository_node,
    symbol_node,
)
from guardian.knowledge.graph_queries import DependencyGraph

YAML = "pkg:pypi/pyyaml@6.0"
REQUESTS = "pkg:pypi/requests@2.0"


def sym(path, qualified, start, end, parent=None, kind=SymbolKind.FUNCTION):
    return Symbol(
        id=f"{path}::{qualified}",
        name=qualified.rsplit(".", 1)[-1],
        qualified_name=qualified,
        kind=kind,
        path=path,
        span=Span(start_line=start, end_line=end),
        parent_id=f"{path}::{parent}" if parent else None,
    )


def file_index(path, symbols=()):
    return FileIndex(
        path=path,
        language=SourceLanguage.PYTHON,
        sha256="0" * 64,
        size=1,
        line_count=50,
        symbols=list(symbols),
    )


def ext_import(line, module, ref=YAML, path="app.py"):
    return ResolvedImport(
        path=path,
        line=line,
        module=module,
        style=ImportStyle.IMPORT,
        target=ImportTarget.EXTERNAL,
        package="pyyaml",
        component_ref=ref,
    )


def ext_call(line, member, caller, ref=YAML):
    return ResolvedCall(
        path="app.py",
        line=line,
        callee=f"yaml.{member}",
        caller_id=f"app.py::{caller}" if caller else None,
        package="pyyaml",
        member=member,
        component_ref=ref,
    )


def internal_call(line, caller, target):
    return ResolvedCall(
        path="app.py",
        line=line,
        callee=target.rsplit("::", 1)[-1],
        caller_id=f"app.py::{caller}" if caller else None,
        target_symbol_id=target,
    )


@pytest.fixture
def profile():
    return RepositoryProfile(
        name="shop",
        root="/work/shop",
        total_files=2,
        total_bytes=2,
        git=GitInfo(is_repository=False),
    )


@pytest.fixture
def sbom():
    return Sbom(
        spec_version="1.5",
        generator="test",
        root_ref="root",
        components=[
            Component(ref=YAML, name="pyyaml", version="6.0"),
            Component(ref="pkg:pypi/six@1", name="six", version="1"),
        ],
        edges=[
            DependencyEdge(source="root", target=YAML),
            DependencyEdge(source=YAML, target="pkg:pypi/six@1"),
        ],
    )


@pytest.fixture
def index():
    app = file_index(
        "app.py",
        [
            sym("app.py", "Service", 3, 9, kind=SymbolKind.CLASS),
            sym("app.py", "Service.load", 4, 6, "Service", SymbolKind.METHOD),
            sym("app.py", "main", 11, 20),
        ],
    )
    util = file_index("util.py", [sym("util.py", "helper", 1, 2)])
    imports = [
        ext_import(1, "yaml"),
        ext_import(3, "yaml.loader"),
        ext_import(2, "yaml"),
        ext_import(4, "requests", ref=REQUESTS),  # not in the SBOM: skipped
        ResolvedImport(
            path="app.py",
            line=5,
            module="util",
            style=ImportStyle.FROM,
            target=ImportTarget.INTERNAL,
            target_path="util.py",
        ),
        ResolvedImport(
            path="app.py",
            line=6,
            module="os",
            style=ImportStyle.IMPORT,
            target=ImportTarget.STDLIB,
            package="os",
        ),
    ]
    calls = [
        ext_call(5, "load", "Service.load"),
        ext_call(14, "load", "main"),
        ext_call(15, "dump", "main"),
        ext_call(16, "load", "main"),
        ext_call(17, "get", "main", ref=REQUESTS),  # unknown component: skipped
        internal_call(13, "main", "app.py::Service.load"),
        internal_call(22, None, "app.py::main"),  # collides with file -DEFINES-> main
        internal_call(23, None, "util.py::helper"),
        ext_call(24, "safe_load", None),
        ResolvedCall(path="app.py", line=25, callee="print", caller_id="app.py::main"),
    ]
    return CodeIndex(files=[app, util], imports=imports, calls=calls)


@pytest.fixture
def graph(profile, sbom, index):
    return build_knowledge_graph(profile, sbom, code_index=index)


def test_symbol_nodes_and_defines(graph):
    service = symbol_node("app.py::Service")
    assert graph.nodes[service]["type"] is NodeType.SYMBOL
    assert graph.nodes[service]["symbol"].qualified_name == "Service"
    assert graph.edges[file_node("app.py"), service]["relation"] is Relation.DEFINES
    method = symbol_node("app.py::Service.load")
    assert graph.edges[service, method]["relation"] is Relation.DEFINES
    assert not graph.has_edge(file_node("app.py"), method)
    assert graph.edges[file_node("util.py"), symbol_node("util.py::helper")]["relation"] is (
        Relation.DEFINES
    )


def test_source_files_are_contained(graph):
    repo = repository_node("shop")
    for path in ("app.py", "util.py"):
        node = file_node(path)
        assert graph.nodes[node]["type"] is NodeType.FILE
        assert graph.nodes[node]["language"] is SourceLanguage.PYTHON
        assert graph.edges[repo, node]["relation"] is Relation.CONTAINS


def test_import_edges_merge(graph):
    edge = graph.edges[file_node("app.py"), component_node(YAML)]
    assert edge["relation"] is Relation.IMPORTS
    assert edge["lines"] == [1, 2, 3]
    assert edge["modules"] == ["yaml", "yaml.loader"]
    internal = graph.edges[file_node("app.py"), file_node("util.py")]
    assert internal["relation"] is Relation.IMPORTS
    assert internal == {"relation": Relation.IMPORTS, "lines": [5], "modules": ["util"]}


def test_unknown_components_are_skipped(graph):
    assert not graph.has_node(component_node(REQUESTS))
    assert not any(n.startswith("file:os") for n in graph.nodes)


def test_call_edges(graph):
    main = symbol_node("app.py::main")
    into_yaml = graph.edges[main, component_node(YAML)]
    assert into_yaml == {
        "relation": Relation.CALLS,
        "count": 3,
        "lines": [14, 15, 16],
        "members": ["dump", "load"],
    }
    internal = graph.edges[main, symbol_node("app.py::Service.load")]
    assert (internal["relation"], internal["count"], internal["members"]) == (
        Relation.CALLS,
        1,
        [],
    )
    assert graph.edges[symbol_node("app.py::Service.load"), component_node(YAML)]["count"] == 1


def test_module_level_calls(graph):
    app = file_node("app.py")
    assert graph.edges[app, symbol_node("util.py::helper")]["relation"] is Relation.CALLS
    module = graph.edges[app, component_node(YAML)]
    # The file both imports and calls yaml: one DiGraph edge per pair, the IMPORTS is kept.
    assert module["relation"] is Relation.IMPORTS
    # A module-level call to a function the file DEFINES keeps the DEFINES edge.
    assert graph.edges[app, symbol_node("app.py::main")]["relation"] is Relation.DEFINES


def test_module_level_component_call_without_import(profile, sbom):
    index = CodeIndex(files=[file_index("app.py")], calls=[ext_call(3, "safe_load", None)])
    g = build_knowledge_graph(profile, sbom, code_index=index)
    edge = g.edges[file_node("app.py"), component_node(YAML)]
    assert (edge["relation"], edge["members"]) == (Relation.CALLS, ["safe_load"])


def test_call_lines_capped_and_merged_on_reapply(profile, sbom):
    index = CodeIndex(
        files=[file_index("app.py", [sym("app.py", "f", 1, 100)])],
        calls=[ext_call(line, "load", "f") for line in range(30, 0, -1)],
    )
    g = build_knowledge_graph(profile, sbom, code_index=index)
    edge = g.edges[symbol_node("app.py::f"), component_node(YAML)]
    assert edge["count"] == 30
    assert edge["lines"] == list(range(1, 21))
    add_code_layer(g, profile, index)  # same pair again: merged, never duplicated
    edge = g.edges[symbol_node("app.py::f"), component_node(YAML)]
    assert (edge["count"], edge["lines"], edge["members"]) == (60, list(range(1, 21)), ["load"])


def test_existing_edge_with_other_relation_is_kept(profile, sbom, index):
    g = build_knowledge_graph(profile, sbom)
    g.add_node(file_node("app.py"), type=NodeType.FILE, path="app.py", kind="source")
    g.add_edge(file_node("app.py"), file_node("util.py"), relation=Relation.MODIFIES)
    add_code_layer(g, profile, index)
    assert g.edges[file_node("app.py"), file_node("util.py")] == {"relation": Relation.MODIFIES}


def test_build_without_code_index(profile, sbom, graph):
    plain = build_knowledge_graph(profile, sbom)
    assert not any(d["type"] is NodeType.SYMBOL for _, d in plain.nodes(data=True))
    assert any(d["type"] is NodeType.SYMBOL for _, d in graph.nodes(data=True))
    positional = build_knowledge_graph(profile, sbom, [], [])
    assert set(positional.nodes) == set(plain.nodes)


def test_code_layer_with_security_layer(profile, sbom, index):
    finding = Finding(
        id="f1",
        kind=FindingKind.CODE,
        title="t",
        severity=Severity.HIGH,
        tool="semgrep",
        path="app.py",
        start_line=5,
        details=CodeDetails(rule_id="r", message="m"),
    )
    g = build_knowledge_graph(profile, sbom, [finding], [], code_index=index)
    assert g.edges[file_node("app.py"), "finding:f1"]["relation"] is Relation.AFFECTED_BY
    assert g.edges[file_node("app.py"), symbol_node("app.py::Service")]["relation"] is (
        Relation.DEFINES
    )


# --- Queries -----------------------------------------------------------------------------


def test_code_queries(graph):
    q = DependencyGraph(graph)
    assert q.symbol("app.py::main").kind is SymbolKind.FUNCTION
    assert q.symbol("app.py::nope") is None
    assert q.importers_of(YAML) == ["app.py"]
    assert q.importers_of("pkg:pypi/six@1") == []
    assert q.importers_of("missing") == []
    assert q.callers_into(YAML) == [
        ("app.py::Service.load", ["load"]),
        ("app.py::main", ["dump", "load"]),
    ]
    assert q.callers_into("missing") == []
    assert q.is_imported(YAML)
    assert not q.is_imported("pkg:pypi/six@1")
    assert not q.is_imported("missing")
    assert q.callers_of_symbol("app.py::Service.load") == ["app.py::main"]
    assert q.callers_of_symbol("util.py::helper") == ["file:app.py"]
    assert q.callees_of_symbol("app.py::main") == ["app.py::Service.load", component_node(YAML)]
    assert q.callees_of_symbol("missing") == []


def test_is_imported_by_call_only(profile, sbom):
    index = CodeIndex(files=[file_index("app.py")], calls=[ext_call(3, "safe_load", None)])
    q = DependencyGraph(build_knowledge_graph(profile, sbom, code_index=index))
    assert q.is_imported(YAML)
    assert q.importers_of(YAML) == []
    assert q.callers_into(YAML) == [("file:app.py", ["safe_load"])]


def test_dependency_queries_unaffected(profile, sbom, graph):
    plain = DependencyGraph(build_dependency_graph(profile, sbom))
    code = DependencyGraph(graph)
    assert code.components() == plain.components()
    assert code.direct_dependencies() == plain.direct_dependencies()
    assert code.depths() == plain.depths() == {YAML: 1, "pkg:pypi/six@1": 2}
    assert code.introduction_paths("pkg:pypi/six@1") == plain.introduction_paths("pkg:pypi/six@1")
    assert code.dependents_of(YAML) == []
    assert code.transitive_dependencies(YAML) == plain.transitive_dependencies(YAML)
    assert code.findings() == []


def test_real_indexer(make_repo):
    root = make_repo(
        {
            "pyproject.toml": '[project]\nname = "demo"\ndependencies = []\n',
            "pkg/__init__.py": "",
            "pkg/util.py": "def helper():\n    return 1\n",
            "pkg/app.py": (
                "from pkg.util import helper\n\n"
                "class Service:\n    def run(self):\n        return helper()\n"
            ),
        }
    )
    settings = GuardianSettings(_env_file=None)
    profile = RepositoryProfiler(settings=settings).profile(root)
    index = RepositoryIndexer(settings).index(profile, None)
    q = DependencyGraph(build_knowledge_graph(profile, None, code_index=index))
    assert q.symbol("pkg/app.py::Service.run") is not None
    assert q.graph.edges[file_node("pkg/app.py"), file_node("pkg/util.py")]["relation"] is (
        Relation.IMPORTS
    )
    assert q.callers_of_symbol("pkg/util.py::helper") == ["pkg/app.py::Service.run"]

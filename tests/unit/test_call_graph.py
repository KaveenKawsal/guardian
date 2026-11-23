import time

from guardian.core.models import (
    CallRef,
    Component,
    Ecosystem,
    FileIndex,
    ImportedName,
    ImportRef,
    ImportStyle,
    ImportTarget,
    ResolvedImport,
    Sbom,
    SourceLanguage,
    Span,
    Symbol,
    SymbolKind,
)
from guardian.indexing._resolution_callee import parse_callee
from guardian.indexing.call_graph import resolve_calls
from guardian.indexing.import_resolver import resolve_imports

PY = SourceLanguage.PYTHON
JS = SourceLanguage.JAVASCRIPT
TS = SourceLanguage.TYPESCRIPT


def _sym(path, qn, kind=SymbolKind.FUNCTION, parent=None, start=1, end=100):
    return Symbol(
        id=f"{path}::{qn}",
        name=qn.split(".")[-1].split("@")[0],
        qualified_name=qn,
        kind=kind,
        path=path,
        span=Span(start_line=start, end_line=end),
        parent_id=f"{path}::{parent}" if parent else None,
    )


def _imp(path, module, style=ImportStyle.IMPORT, names=(), alias=None, level=0, line=1):
    return ImportRef(
        path=path,
        line=line,
        module=module,
        style=style,
        level=level,
        names=[
            ImportedName(name=n[0], alias=n[1]) if isinstance(n, tuple) else ImportedName(name=n)
            for n in names
        ],
        module_alias=alias,
    )


def _call(path, callee, caller=None, line=50):
    return CallRef(
        path=path, line=line, callee=callee, caller_id=f"{path}::{caller}" if caller else None
    )


def _file(path, language, symbols=(), imports=(), calls=()):
    return FileIndex(
        path=path,
        language=language,
        sha256="0" * 64,
        size=1,
        line_count=100,
        symbols=list(symbols),
        imports=list(imports),
        calls=list(calls),
    )


def _run(files, sbom=None, declared=None, extra_repo=()):
    repo = [f.path for f in files] + list(extra_repo)
    imports = resolve_imports(files, repo_files=repo, sbom=sbom, declared=declared or {})
    return resolve_calls(files, imports)


def _targets(results):
    return [(r.target_symbol_id, r.package, r.member) for r in results]


# --- Callee parsing ---------------------------------------------------------------------


def test_parse_callee_segments():
    segs = parse_callee("requests.get(url, x=(1, 2)).json")
    assert [(s.name, s.computed) for s in segs] == [
        ("requests", False),
        ("get", True),
        ("json", False),
    ]
    assert [s.name for s in parse_callee("a?.b[0].c")] == ["a", "b", "c"]
    assert parse_callee("<expr>")[0].name == "<expr>"


# --- Python -----------------------------------------------------------------------------


def test_python_external_member_calls():
    path = "app.py"
    sbom = Sbom(
        spec_version="1.5",
        generator="t",
        components=[Component(ref="pyyaml@6", name="pyyaml", ecosystem=Ecosystem.PYTHON)],
    )
    files = [
        _file(
            path,
            PY,
            imports=[
                _imp(path, "yaml", line=1),
                _imp(path, "yaml", style=ImportStyle.FROM, names=[("load", "l")], line=2),
                _imp(path, "os.path", line=3),
                _imp(path, "requests", line=4),
                _imp(path, "os.path", alias="osp", line=5),
                _imp(path, "os.path", style=ImportStyle.FROM, names=["join"], line=6),
            ],
            calls=[
                _call(path, "yaml.load"),
                _call(path, "l"),
                _call(path, "os.path.join"),
                _call(path, "requests.get().json"),
                _call(path, "osp.join"),
                _call(path, "join"),
                _call(path, "yaml"),
            ],
        )
    ]
    results = _run(files, sbom=sbom)
    assert _targets(results) == [
        (None, "pyyaml", "load"),
        (None, "pyyaml", "load"),
        (None, "os", "path.join"),
        (None, "requests", "get"),
        (None, "os", "path.join"),
        (None, "os", "path.join"),
        (None, "pyyaml", None),
    ]
    assert results[0].component_ref == "pyyaml@6"
    assert results[3].component_ref is None


def test_python_internal_module_and_member_bindings():
    files = [
        _file(
            "pkg/models.py",
            PY,
            symbols=[
                _sym("pkg/models.py", "User", SymbolKind.CLASS),
                _sym("pkg/models.py", "User.save", SymbolKind.METHOD, parent="User"),
                _sym("pkg/models.py", "helper"),
            ],
        ),
        _file("pkg/__init__.py", PY, symbols=[_sym("pkg/__init__.py", "init_app")]),
        _file(
            "main.py",
            PY,
            imports=[
                _imp("main.py", "pkg.models", line=1),
                _imp("main.py", "pkg.models", alias="m", line=2),
                _imp(
                    "main.py", "pkg.models", style=ImportStyle.FROM, names=[("User", "U")], line=3
                ),
                _imp(
                    "main.py", "pkg", style=ImportStyle.FROM, names=["models", "init_app"], line=4
                ),
            ],
            calls=[
                _call("main.py", "pkg.models.helper"),
                _call("main.py", "m.User.save"),
                _call("main.py", "U"),
                _call("main.py", "U.save"),
                _call("main.py", "models.helper"),
                _call("main.py", "init_app"),
                _call("main.py", "pkg.init_app"),
                _call("main.py", "m.missing"),
                _call("main.py", "U().save"),
                _call("main.py", "m.User().save"),
                _call("main.py", "m.helper().x"),
            ],
        ),
    ]
    assert [r.target_symbol_id for r in _run(files)] == [
        "pkg/models.py::helper",
        "pkg/models.py::User.save",
        "pkg/models.py::User",
        "pkg/models.py::User.save",
        "pkg/models.py::helper",
        "pkg/__init__.py::init_app",
        "pkg/__init__.py::init_app",
        None,
        "pkg/models.py::User.save",
        "pkg/models.py::User.save",
        None,
    ]


def test_python_relative_and_star_imports():
    files = [
        _file("app/__init__.py", PY),
        _file("app/views.py", PY, symbols=[_sym("app/views.py", "index")]),
        _file("app/utils.py", PY, symbols=[_sym("app/utils.py", "slug")]),
        _file(
            "app/main.py",
            PY,
            imports=[
                _imp("app/main.py", "", style=ImportStyle.FROM, names=["views"], level=1),
                _imp("app/main.py", "utils", style=ImportStyle.FROM, names=["*"], level=1),
                _imp("os", "os", style=ImportStyle.FROM, names=["*"]),
            ],
            calls=[
                _call("app/main.py", "views.index"),
                _call("app/main.py", "slug"),
                _call("app/main.py", "unknown"),
                _call("app/main.py", "unknown()"),
            ],
        ),
    ]
    assert [r.target_symbol_id for r in _run(files)] == [
        "app/views.py::index",
        "app/utils.py::slug",
        None,
        None,
    ]


def test_python_self_cls_methods_and_nested():
    path = "svc.py"
    symbols = [
        _sym(path, "Service", SymbolKind.CLASS),
        _sym(path, "Service.run", SymbolKind.METHOD, parent="Service"),
        _sym(path, "Service.save", SymbolKind.METHOD, parent="Service"),
        _sym(path, "Service.run.inner", parent="Service.run"),
        _sym(path, "Service.run.inner.deeper", parent="Service.run.inner"),
        _sym(path, "top"),
        _sym(path, "top.nested", parent="top"),
        _sym(path, "top@20", start=20),
    ]
    calls = [
        _call(path, "self.save", caller="Service.run"),
        _call(path, "cls.save", caller="Service.run.inner"),
        _call(path, "self.missing", caller="Service.run"),
        _call(path, "self.session.get", caller="Service.run"),
        _call(path, "self.save", caller="top"),
        _call(path, "self.save().x", caller="Service.run"),
        _call(path, "inner", caller="Service.run"),
        _call(path, "deeper", caller="Service.run.inner"),
        _call(path, "nested", caller="top"),
        _call(path, "save", caller="Service.run"),
        _call(path, "top"),
        _call(path, "Service"),
        _call(path, "Service.save"),
        _call(path, "Service.nope"),
        _call(path, "eval"),
        _call(path, "<expr>"),
        _call(path, "self.save", caller=None),
    ]
    results = _run([_file(path, PY, symbols=symbols, calls=calls)])
    assert [r.target_symbol_id for r in results] == [
        f"{path}::Service.save",
        f"{path}::Service.save",
        None,
        None,
        None,
        None,
        f"{path}::Service.run.inner",
        f"{path}::Service.run.inner.deeper",
        f"{path}::top.nested",
        None,
        f"{path}::top@20",  # the later redefinition wins
        f"{path}::Service",
        f"{path}::Service.save",
        None,
        None,
        None,
        None,
    ]
    assert all(r.package is None and r.member is None for r in results)
    assert results[14].callee == "eval"
    assert results[0].caller_id == f"{path}::Service.run"


def test_python_local_definition_after_import_wins():
    path = "a.py"
    files = [
        _file(
            path,
            PY,
            symbols=[_sym(path, "load", start=10, end=12)],
            imports=[_imp(path, "yaml", style=ImportStyle.FROM, names=["load"], line=1)],
            calls=[_call(path, "load")],
        )
    ]
    assert _targets(_run(files)) == [(f"{path}::load", None, None)]


def test_python_unresolved_import_binds_nothing():
    path = "a.py"
    files = [
        _file(
            path,
            PY,
            imports=[_imp(path, "missing", style=ImportStyle.FROM, names=["x"], level=1)],
            calls=[_call(path, "x")],
        )
    ]
    assert _targets(_run(files)) == [(None, None, None)]


def test_hand_built_resolved_imports_and_missing_match():
    path = "a.py"
    ref = _imp(path, "yaml")
    files = [
        _file(
            path,
            PY,
            imports=[ref, _imp(path, "json", line=2)],
            calls=[_call(path, "yaml.safe_load"), _call(path, "json.loads")],
        )
    ]
    imports = [
        ResolvedImport(
            path=path,
            line=1,
            module="yaml",
            style=ImportStyle.IMPORT,
            target=ImportTarget.EXTERNAL,
            package="pyyaml",
            component_ref="c1",
        )
    ]
    results = resolve_calls(files, imports)
    assert (results[0].package, results[0].member, results[0].component_ref) == (
        "pyyaml",
        "safe_load",
        "c1",
    )
    assert results[1].package is None


def test_namespace_package_internal_binding_has_no_target():
    files = [
        _file("ns/mod.py", PY, symbols=[_sym("ns/mod.py", "f")]),
        _file(
            "main.py",
            PY,
            imports=[_imp("main.py", "ns", style=ImportStyle.FROM, names=["mod"])],
            calls=[_call("main.py", "mod.f")],
        ),
    ]
    assert [r.target_symbol_id for r in _run(files)] == [None]


# --- JavaScript / TypeScript ------------------------------------------------------------


def test_js_external_bindings():
    path = "src/app.js"
    files = [
        _file(
            path,
            JS,
            imports=[
                _imp(path, "lodash", style=ImportStyle.REQUIRE, alias="_", line=1),
                _imp(path, "express", style=ImportStyle.ES, names=[("default", "express")], line=2),
                _imp(path, "fs", style=ImportStyle.ES, names=["readFile"], line=3),
                _imp(path, "node:child_process", style=ImportStyle.ES, alias="cp", line=4),
                _imp(path, "lodash/fp", style=ImportStyle.ES, names=[("default", "fp")], line=5),
                _imp(path, "lodash/template", style=ImportStyle.REQUIRE, alias="tpl", line=6),
                _imp(path, "axios", style=ImportStyle.ES, names=[("*", "ax")], line=7),
                _imp(path, "@scope/pkg", style=ImportStyle.ES, names=["thing"], line=8),
            ],
            calls=[
                _call(path, "_.template"),
                _call(path, "express"),
                _call(path, "express.Router"),
                _call(path, "readFile"),
                _call(path, "cp.exec"),
                _call(path, "fp.map"),
                _call(path, "fp"),
                _call(path, "tpl"),
                _call(path, "ax.get"),
                _call(path, "thing"),
                _call(path, "res.send"),
                _call(path, "this.save"),
            ],
        )
    ]
    assert _targets(_run(files)) == [
        (None, "lodash", "template"),
        (None, "express", "default"),
        (None, "express", "Router"),
        (None, "fs", "readFile"),
        (None, "child_process", "exec"),
        (None, "lodash", "fp.map"),
        (None, "lodash", "fp"),
        (None, "lodash", "template"),
        (None, "axios", "get"),
        (None, "@scope/pkg", "thing"),
        (None, None, None),
        (None, None, None),
    ]


def test_js_internal_bindings_and_this():
    lib = "src/lib.ts"
    app = "src/app.ts"
    files = [
        _file(
            lib,
            TS,
            symbols=[
                _sym(lib, "helper"),
                _sym(lib, "Repo", SymbolKind.CLASS),
                _sym(lib, "Repo.find", SymbolKind.METHOD, parent="Repo"),
            ],
        ),
        _file(
            "src/all.ts",
            TS,
            symbols=[_sym("src/all.ts", "starred")],
        ),
        _file(
            app,
            TS,
            symbols=[
                _sym(app, "Ctl", SymbolKind.CLASS),
                _sym(app, "Ctl.handle", SymbolKind.METHOD, parent="Ctl"),
                _sym(app, "Ctl.load", SymbolKind.METHOD, parent="Ctl"),
                _sym(app, "Ctl.handle.cb", parent="Ctl.handle"),
            ],
            imports=[
                _imp(
                    app, "./lib.js", style=ImportStyle.ES, names=["helper", ("Repo", "R")], line=1
                ),
                _imp(app, "./lib", style=ImportStyle.ES, names=[("*", "lib")], line=2),
                _imp(app, "./lib", style=ImportStyle.ES, names=[("default", "d")], line=3),
                _imp(app, "./all", style=ImportStyle.ES, names=["*"], line=4),
                _imp(app, "./lib", style=ImportStyle.REQUIRE, alias="req", line=5),
            ],
            calls=[
                _call(app, "helper", caller="Ctl.handle"),
                _call(app, "R.find"),
                _call(app, "lib.helper"),
                _call(app, "d"),
                _call(app, "d.helper"),
                _call(app, "starred"),
                _call(app, "req.Repo.find"),
                _call(app, "this.load", caller="Ctl.handle"),
                _call(app, "this.load", caller="Ctl.handle.cb"),
                _call(app, "self.load", caller="Ctl.handle"),
                _call(app, "new R().find"),
                _call(app, "R().find"),
            ],
        ),
    ]
    assert [r.target_symbol_id for r in _run(files)] == [
        f"{lib}::helper",
        f"{lib}::Repo.find",
        f"{lib}::helper",
        None,
        f"{lib}::helper",
        "src/all.ts::starred",
        f"{lib}::Repo.find",
        f"{app}::Ctl.load",
        f"{app}::Ctl.load",
        None,
        None,
        f"{lib}::Repo.find",
    ]


# --- Robustness and performance ---------------------------------------------------------


def test_order_preserved_across_files_and_odd_callees():
    files = [
        _file("a.py", PY, calls=[_call("a.py", "", line=1), _call("a.py", "x" * 200, line=2)]),
        _file("b.js", JS, calls=[_call("b.js", "((a))", line=3), _call("b.js", "a..b", line=4)]),
    ]
    results = _run(files)
    assert [r.line for r in results] == [1, 2, 3, 4]
    assert all(r.target_symbol_id is None for r in results)


def test_performance_1000_files_30_calls():
    files = []
    for i in range(1000):
        path = f"pkg/m{i}.py"
        other = f"m{(i + 1) % 1000}"
        symbols = [_sym(path, f"f{j}") for j in range(10)]
        imports = [
            _imp(path, f"pkg.{other}", alias="o", line=1),
            _imp(path, "yaml", line=2),
            _imp(path, "os.path", line=3),
        ]
        calls = []
        for j in range(10):
            calls += [
                _call(path, f"o.f{j}"),
                _call(path, "yaml.load"),
                _call(path, f"f{j}", caller="f0"),
            ]
        files.append(_file(path, PY, symbols=symbols, imports=imports, calls=calls))
    start = time.perf_counter()
    results = _run(files, extra_repo=["pkg/__init__.py"])
    elapsed = time.perf_counter() - start
    assert len(results) == 30_000
    assert results[0].target_symbol_id == "pkg/m1.py::f0"
    assert results[1].member == "load"
    assert elapsed < 5.0

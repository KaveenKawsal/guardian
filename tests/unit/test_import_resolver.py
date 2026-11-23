from guardian.core.models import (
    Component,
    DependencyEdge,
    Ecosystem,
    FileIndex,
    ImportedName,
    ImportRef,
    ImportStyle,
    ImportTarget,
    Sbom,
    SourceLanguage,
)
from guardian.indexing.import_resolver import resolve_imports

PY = SourceLanguage.PYTHON
JS = SourceLanguage.JAVASCRIPT
TS = SourceLanguage.TYPESCRIPT


def _file(path, language, *imports):
    return FileIndex(
        path=path,
        language=language,
        sha256="0" * 64,
        size=1,
        line_count=1,
        imports=list(imports),
    )


def _imp(path, module, style=ImportStyle.IMPORT, level=0, names=(), alias=None, line=1):
    return ImportRef(
        path=path,
        line=line,
        module=module,
        style=style,
        level=level,
        names=[ImportedName(name=n) for n in names],
        module_alias=alias,
    )


def _resolve_one(path, language, ref, repo, sbom=None, declared=None):
    result = resolve_imports(
        [_file(path, language, ref)], repo_files=repo, sbom=sbom, declared=declared or {}
    )
    assert len(result) == 1
    return result[0]


def _py(module, repo, path="app/main.py", level=0, style=ImportStyle.FROM, **kw):
    ref = _imp(path, module, style=style, level=level, names=("x",))
    return _resolve_one(path, PY, ref, repo, **kw)


def _js(module, repo, path="src/app.js", language=JS, **kw):
    ref = _imp(path, module, style=ImportStyle.ES, names=("default",))
    return _resolve_one(path, language, ref, repo, **kw)


# --- Python -----------------------------------------------------------------------------


def test_python_relative_module_and_package():
    repo = ["app/__init__.py", "app/main.py", "app/models.py", "app/sub/__init__.py"]
    r = _py("models", repo, level=1)
    assert (r.target, r.target_path) == (ImportTarget.INTERNAL, "app/models.py")
    assert _py(".models", repo).target_path == "app/models.py"  # dots in module text
    assert _py("sub", repo, level=1).target_path == "app/sub/__init__.py"
    assert _py("", repo, level=1).target_path == "app/__init__.py"


def test_python_relative_parent_levels_and_escape():
    repo = ["pkg/__init__.py", "pkg/util.py", "pkg/a/__init__.py", "pkg/a/b.py"]
    assert _py("util", repo, path="pkg/a/b.py", level=2).target_path == "pkg/util.py"
    assert _py("x", repo, path="pkg/a/b.py", level=5).target is ImportTarget.UNRESOLVED
    assert _py("missing", repo, path="pkg/a/b.py", level=1).target is ImportTarget.UNRESOLVED


def test_python_relative_namespace_package():
    repo = ["ns/mod.py", "ns/inner/thing.py"]
    r = _py("", repo, path="ns/mod.py", level=1)
    assert (r.target, r.target_path) == (ImportTarget.INTERNAL, None)
    r = _py("inner", repo, path="ns/mod.py", level=1)
    assert (r.target, r.target_path) == (ImportTarget.INTERNAL, None)


def test_python_relative_prefix_module():
    repo = ["app/__init__.py", "app/main.py", "app/models.py"]
    assert _py("models.User", repo, level=1).target_path == "app/models.py"


def test_python_absolute_root_src_and_package_parent():
    repo = ["app/__init__.py", "app/main.py", "app/db.py", "src/lib1/core.py"]
    assert _py("app.db", repo).target_path == "app/db.py"
    assert _py("lib1.core", repo).target_path == "src/lib1/core.py"
    repo2 = ["backend/app/__init__.py", "backend/app/api/__init__.py", "backend/app/api/v.py"]
    r = _py("app.api", repo2, path="backend/app/api/v.py")
    assert r.target_path == "backend/app/api/__init__.py"


def test_python_absolute_script_directory_root():
    repo = ["tools/run.py", "tools/helpers.py"]
    assert _py("helpers", repo, path="tools/run.py").target_path == "tools/helpers.py"


def test_python_absolute_prefers_longest_then_shortest_root():
    repo = ["pkg/__init__.py", "src/pkg/__init__.py", "src/pkg/deep.py", "lib/pkg/__init__.py"]
    assert _py("pkg.deep", repo).target_path == "src/pkg/deep.py"
    assert _py("pkg", repo).target_path == "pkg/__init__.py"


def test_python_absolute_attribute_falls_back_to_module():
    repo = ["pkg/__init__.py", "pkg/module.py"]
    r = _py("pkg.module.Class", repo, style=ImportStyle.IMPORT)
    assert r.target_path == "pkg/module.py"


def test_python_stdlib_and_shadowing():
    repo = ["app/main.py", "logging.py"]
    r = _py("os.path", repo)
    assert (r.target, r.package) == (ImportTarget.STDLIB, "os")
    assert _py("__future__", repo).target is ImportTarget.STDLIB
    assert _py("logging", repo).target_path == "logging.py"


def test_python_namespace_dir_does_not_shadow_stdlib_or_declared():
    repo = ["json/schemas/a.py", "yaml/b.py", "ns/c.py"]
    assert _py("json", repo).target is ImportTarget.STDLIB
    r = _py("yaml", repo, declared={Ecosystem.PYTHON: {"pyyaml"}})
    assert r.target is ImportTarget.EXTERNAL
    r = _py("ns", repo)
    assert (r.target, r.target_path) == (ImportTarget.INTERNAL, None)


def test_python_external_alias_map_and_undeclared():
    assert _py("yaml", []).package == "pyyaml"
    assert _py("PIL.Image", []).package == "pillow"
    assert _py("sklearn.svm", []).package == "scikit-learn"
    assert _py("google.protobuf", []).package == "protobuf"
    assert _py("Flask_Login", []).package == "flask-login"
    r = _py("totally_unknown", [])
    assert (r.target, r.package, r.component_ref) == (
        ImportTarget.EXTERNAL,
        "totally-unknown",
        None,
    )


def test_python_alias_candidates_prefer_declared():
    declared = {Ecosystem.PYTHON: {"psycopg2-binary"}}
    assert _py("psycopg2", [], declared=declared).package == "psycopg2-binary"
    assert _py("psycopg2", []).package == "psycopg2"
    declared = {Ecosystem.PYTHON: {"google-cloud-storage"}}
    assert _py("google.cloud.storage", [], declared=declared).package == "google-cloud-storage"


def test_python_invalid_module_unresolved():
    assert _py("not a module!", []).target is ImportTarget.UNRESOLVED
    assert _py("", [], level=0).target is ImportTarget.UNRESOLVED


# --- SBOM matching ----------------------------------------------------------------------


def _component(ref, name, eco, group=None, direct=None, purl_type=None):
    return Component(
        ref=ref, name=name, group=group, ecosystem=eco, direct=direct, purl_type=purl_type
    )


def test_sbom_match_prefers_direct_then_depth_then_ref():
    sbom = Sbom(
        spec_version="1.5",
        generator="t",
        root_ref="root",
        components=[
            _component("pkg:pypi/pyyaml@5", "PyYAML", Ecosystem.PYTHON),
            _component("pkg:pypi/pyyaml@6", "pyyaml", Ecosystem.PYTHON, direct=True),
            _component("b-lodash@3", "lodash", Ecosystem.NODE),
            _component("a-lodash@4", "lodash", Ecosystem.NODE),
            _component("c-lodash@2", "lodash", Ecosystem.NODE),
            _component("scoped", "core", None, group="@angular", purl_type="npm"),
            _component("scoped2", "router", Ecosystem.NODE, group="angular"),
            _component("mvn", "x", Ecosystem.JAVA),
            _component("noeco", "y", None),
        ],
        edges=[
            DependencyEdge(source="root", target="b-lodash@3"),
            DependencyEdge(source="b-lodash@3", target="a-lodash@4"),
            DependencyEdge(source="b-lodash@3", target="c-lodash@2"),
        ],
    )
    assert _py("yaml", [], sbom=sbom).component_ref == "pkg:pypi/pyyaml@6"
    assert _js("lodash", [], sbom=sbom).component_ref == "b-lodash@3"
    assert _js("@angular/core/testing", [], sbom=sbom).component_ref == "scoped"
    assert _js("@angular/router", [], sbom=sbom).component_ref == "scoped2"
    assert _js("express", [], sbom=sbom).component_ref is None
    no_root = sbom.model_copy(update={"root_ref": None})
    assert _js("lodash", [], sbom=no_root).component_ref == "a-lodash@4"


# --- JavaScript / TypeScript ------------------------------------------------------------


def test_js_relative_extensions_and_index():
    repo = ["src/app.js", "src/util.ts", "src/lib/index.js", "src/data.json", "src/x.js"]
    assert _js("./util", repo).target_path == "src/util.ts"
    assert _js("./lib", repo).target_path == "src/lib/index.js"
    assert _js("./data.json", repo).target_path == "src/data.json"
    assert _js("./x.js", repo).target_path == "src/x.js"
    assert _js("../src/util", repo).target_path == "src/util.ts"
    assert _js(".", ["src/app.js", "src/index.ts"]).target_path == "src/index.ts"
    assert _js("/src/util", repo).target_path == "src/util.ts"
    assert _js("./missing", repo).target is ImportTarget.UNRESOLVED


def test_js_specifier_maps_to_typescript_source():
    repo = ["src/app.ts", "src/server.ts", "src/view.tsx", "src/m.mts"]
    assert _js("./server.js", repo, path="src/app.ts", language=TS).target_path == "src/server.ts"
    assert _js("./view.jsx", repo, path="src/app.ts").target_path == "src/view.tsx"
    assert _js("./m.mjs", repo, path="src/app.ts").target_path == "src/m.mts"


def test_js_root_escape_unresolved():
    assert _js("../../../etc/passwd", ["src/app.js"]).target is ImportTarget.UNRESOLVED


def test_js_builtins():
    r = _js("node:fs", [])
    assert (r.target, r.package) == (ImportTarget.STDLIB, "fs")
    assert _js("node:fs/promises", []).package == "fs"
    r = _js("fs/promises", [])
    assert (r.target, r.package) == (ImportTarget.STDLIB, "fs")
    assert _js("child_process", []).target is ImportTarget.STDLIB
    assert _js("node:", []).target is ImportTarget.UNRESOLVED


def test_js_declared_polyfill_beats_builtin_name():
    r = _js("events", [], declared={Ecosystem.NODE: {"events"}})
    assert (r.target, r.package) == (ImportTarget.EXTERNAL, "events")


def test_js_bare_and_scoped_packages():
    r = _js("lodash/fp", [])
    assert (r.target, r.package) == (ImportTarget.EXTERNAL, "lodash")
    assert _js("@types/node", []).package == "@types/node"
    assert _js("@scope", []).target is ImportTarget.UNRESOLVED
    assert _js("lodash.merge", []).package == "lodash.merge"
    assert _js("style-loader!./x.css?inline", ["src/app.js", "src/x.css"]).target_path == (
        "src/x.css"
    )
    assert _js("https://cdn.example/x.js", []).target is ImportTarget.UNRESOLVED
    assert _js("   ", []).target is ImportTarget.UNRESOLVED


def test_js_path_aliases():
    repo = ["src/app.js", "src/components/Button.tsx", "lib/helpers.js", "src/internal/x.ts"]
    assert _js("@/components/Button", repo).target_path == "src/components/Button.tsx"
    assert _js("~/components/Button", repo).target_path == "src/components/Button.tsx"
    assert _js("#internal/x", repo).target_path == "src/internal/x.ts"
    assert _js("lib/helpers", repo).target_path == "lib/helpers.js"
    assert _js("components/Button", repo).target_path == "src/components/Button.tsx"
    assert _js("@/nope", repo).target is ImportTarget.UNRESOLVED
    assert _js("lib/nope", repo).target is ImportTarget.UNRESOLVED
    r = _js("lib", repo, declared={Ecosystem.NODE: {"lib"}})
    assert r.target is ImportTarget.EXTERNAL


# --- General ----------------------------------------------------------------------------


def test_order_and_mixed_languages_preserved():
    files = [
        _file("a.py", PY, _imp("a.py", "os", line=1), _imp("a.py", "yaml", line=2)),
        _file("b.ts", TS, _imp("b.ts", "./a", style=ImportStyle.ES)),
    ]
    result = resolve_imports(files, repo_files=["a.py", "b.ts", "a.ts"], sbom=None, declared={})
    assert [r.module for r in result] == ["os", "yaml", "./a"]
    assert [r.target for r in result] == [
        ImportTarget.STDLIB,
        ImportTarget.EXTERNAL,
        ImportTarget.INTERNAL,
    ]
    assert result[2].target_path == "a.ts"
    assert result[0].style is ImportStyle.IMPORT


def test_windows_style_repo_paths_are_normalized():
    r = _py("app.db", [".\\app\\db.py", "", "app/db.py"])
    assert r.target_path == "app/db.py"

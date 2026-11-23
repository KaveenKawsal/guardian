import json

import pytest

from guardian.core.models import (
    CallRef,
    EntryPointKind,
    FileIndex,
    ResolvedCall,
    SourceLanguage,
    Span,
    Symbol,
    SymbolKind,
)
from guardian.indexing.entry_points import detect_entry_points, route_from_decorator

PY = SourceLanguage.PYTHON
TS = SourceLanguage.TYPESCRIPT


def _file(path, language=PY, symbols=(), calls=()):
    return FileIndex(
        path=path,
        language=language,
        sha256="x",
        size=1,
        line_count=10,
        symbols=list(symbols),
        calls=list(calls),
    )


def _func(path, name, decorators, line=3):
    return Symbol(
        id=f"{path}::{name}",
        name=name,
        qualified_name=name,
        kind=SymbolKind.FUNCTION,
        path=path,
        span=Span(start_line=line, end_line=line + 2),
        decorators=decorators,
    )


def _call(path, callee, line=1, args=(), caller=None):
    return CallRef(path=path, line=line, callee=callee, literal_args=list(args), caller_id=caller)


def _detect(files=(), calls=(), main_guard_paths=(), manifests=None):
    return detect_entry_points(
        list(files), list(calls), main_guard_paths=set(main_guard_paths), manifests=manifests or {}
    )


def _summary(entries):
    return [(e.path, e.line, e.kind, e.detail, e.symbol_id) for e in entries]


def test_dunder_main_and_main_guard():
    entries = _detect([_file("pkg/__main__.py"), _file("tool.py")], main_guard_paths=["tool.py"])
    assert _summary(entries) == [
        ("pkg/__main__.py", None, EntryPointKind.DUNDER_MAIN, "__main__.py", None),
        ("tool.py", None, EntryPointKind.MAIN_GUARD, "if __name__ == '__main__'", None),
    ]


def test_route_from_decorator_variants():
    assert route_from_decorator('app.get("/users")') == "GET /users"
    assert route_from_decorator("@bp.route('/x', methods=['POST'])") == "ROUTE /x"
    assert route_from_decorator('router.api_route("/a")') == "ROUTE /a"
    assert route_from_decorator('app.websocket("/ws")') == "WEBSOCKET /ws"
    assert route_from_decorator("app.post(PATH)") == "POST"
    assert route_from_decorator("functools.lru_cache()") is None
    assert route_from_decorator("staticmethod") is None


def test_python_decorator_routes_win_over_their_call_sites():
    f = _file(
        "api.py",
        symbols=[
            _func("api.py", "users", ['app.get("/users")']),
            _func("api.py", "plain", ["functools.cache"], line=9),
        ],
        calls=[_call("api.py", "app.get", line=2, args=["/users"])],
    )
    assert _summary(_detect([f])) == [
        ("api.py", 3, EntryPointKind.HTTP_ROUTE, "GET /users", "api.py::users")
    ]


def test_js_route_calls():
    f = _file(
        "server.ts",
        TS,
        calls=[
            _call("server.ts", "app.post", line=4, args=["/api/login"], caller="server.ts::setup"),
            _call("server.ts", "router.use", line=5, args=["/rest"]),
            _call("server.ts", "app.get", line=6, args=["port"]),  # config getter, not a route
            _call("server.ts", "get", line=7, args=["/x"]),  # no receiver
            _call("server.ts", "app.get", line=8),
        ],
    )
    assert _summary(_detect([f])) == [
        ("server.ts", 4, EntryPointKind.HTTP_ROUTE, "POST /api/login", "server.ts::setup"),
        ("server.ts", 5, EntryPointKind.HTTP_ROUTE, "USE /rest", None),
    ]


def test_server_listen():
    js = _file(
        "server.js",
        SourceLanguage.JAVASCRIPT,
        calls=[
            _call("server.js", "app.listen", line=10),
            _call("server.js", "http.createServer().listen", line=11),
        ],
    )
    py = _file(
        "main.py",
        calls=[
            _call("main.py", "uvicorn.run", line=3),
            _call("main.py", "app.run", line=4),
            _call("main.py", "sock.listen", line=5),  # Python socket, not a server entry
            _call("main.py", "run", line=6),
        ],
    )
    resolved = [ResolvedCall(path="main.py", line=6, callee="run", package="uvicorn", member="run")]
    kinds = {
        (e.path, e.line, e.detail)
        for e in _detect([js, py], resolved)
        if e.kind is EntryPointKind.SERVER_LISTEN
    }
    assert kinds == {
        ("server.js", 10, "app.listen"),
        ("server.js", 11, "http.createServer().listen"),
        ("main.py", 3, "uvicorn.run"),
        ("main.py", 4, "app.run"),
        ("main.py", 6, "run"),
    }


def test_package_json_entry_points():
    manifest = json.dumps(
        {
            "name": "guardian",
            "main": "index.js",
            "module": "esm/index.js",
            "bin": "dist/cli.js",
            "scripts": {"start": "node server.js", "test": "jest"},
        }
    ).encode()
    multi = json.dumps({"bin": {"a": "a.js", "b": 3}}).encode()
    details = [
        e.detail for e in _detect(manifests={"package.json": manifest, "web/package.json": multi})
    ]
    assert details == [
        "bin guardian -> dist/cli.js",
        "main -> index.js",
        "module -> esm/index.js",
        "scripts.start: node server.js",
        "bin a -> a.js",
    ]


def test_pyproject_entry_points():
    toml = b"""
[project.scripts]
guardian = "guardian.cli:app"
[tool.poetry.scripts]
legacy = "pkg.main:run"
other = { callable = "pkg.other:main" }
"""
    entries = _detect(manifests={"pyproject.toml": toml})
    assert {e.kind for e in entries} == {EntryPointKind.PACKAGE_MAIN}
    assert sorted(e.detail for e in entries) == [
        "script guardian -> guardian.cli:app",
        "script legacy -> pkg.main:run",
        "script other -> pkg.other:main",
    ]


def test_malformed_manifests_are_ignored():
    manifests = {
        "package.json": b"{not json",
        "a/package.json": b"[1, 2]",
        "b/package.json": b'{"main": 5, "bin": [], "scripts": "x"}',
        "pyproject.toml": b"[project\nbroken",
        "c/pyproject.toml": b"\xff\xfe",
        "d/pyproject.toml": b'project = "str"\n[tool]\npoetry = 1',
        "e/pyproject.toml": b"[project]\nscripts = [1]",
        "README.md": b"main",
    }
    assert _detect(manifests=manifests) == []


def test_details_are_bounded_and_printable():
    manifest = json.dumps({"main": "a\x1b[31m" + "x" * 500}).encode()
    (entry,) = _detect(manifests={"package.json": manifest})
    assert len(entry.detail) == 200
    assert "\x1b" not in entry.detail


def test_duplicates_removed_and_sorted():
    f = _file(
        "b.js",
        SourceLanguage.JAVASCRIPT,
        calls=[
            _call("b.js", "app.listen", line=9),
            _call("b.js", "app.listen", line=9),
            _call("b.js", "app.get", line=2, args=["/"]),
        ],
    )
    entries = _detect([_file("a/__main__.py"), f], main_guard_paths=["a/__main__.py"])
    assert [(e.path, e.line) for e in entries] == [
        ("a/__main__.py", None),
        ("a/__main__.py", None),
        ("b.js", 2),
        ("b.js", 9),
    ]


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("test/api/loginSpec.ts", True),
        ("frontend/src/app/login/login.component.spec.ts", True),
        ("src/__tests__/server.test.js", True),
        ("cypress/e2e/login.cy.ts", True),
        ("tests/test_app.py", True),
        ("app/user_test.py", True),
        ("server.ts", False),
        ("routes/login.ts", False),
        ("src/contest.py", False),
        ("src/latest/app.js", False),
    ],
)
def test_is_test_path(path, expected):
    from guardian.indexing.entry_points import is_test_path

    assert is_test_path(path) is expected


def test_test_client_calls_are_not_routes():
    from guardian.core.models import CallRef, FileIndex, SourceLanguage
    from guardian.indexing.entry_points import detect_entry_points

    def file(path):
        call = CallRef(path=path, line=3, callee="request().get", literal_args=["/api/users"])
        return FileIndex(
            path=path,
            language=SourceLanguage.TYPESCRIPT,
            sha256="x",
            size=1,
            line_count=5,
            calls=[call],
        )

    found = detect_entry_points(
        [file("test/api/userSpec.ts"), file("server.ts")], [], main_guard_paths=(), manifests={}
    )
    assert [(e.path, e.detail) for e in found] == [("server.ts", "GET /api/users")]

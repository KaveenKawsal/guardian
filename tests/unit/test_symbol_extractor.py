import hashlib
import os
import random
import time

import pytest

from guardian.core.models import ImportedName, ImportStyle, SourceLanguage, SymbolKind
from guardian.indexing.symbol_extractor import extract_file

PY = SourceLanguage.PYTHON
JS = SourceLanguage.JAVASCRIPT
TS = SourceLanguage.TYPESCRIPT
TSX = SourceLanguage.TSX


def _py(src: str):
    return extract_file("app/m.py", src.encode(), PY)


def _js(src: str, language: SourceLanguage = JS, path: str = "src/m.js"):
    return extract_file(path, src.encode(), language)


def _syms(index):
    return {s.id: s for s in index.symbols}


def _names(ref):
    return [(n.name, n.alias) for n in ref.names]


# --- file metadata ---------------------------------------------------------------------


def test_metadata():
    src = b"def f():\n    pass\n"
    index = extract_file("a.py", src, PY)
    assert index.path == "a.py"
    assert index.language is PY
    assert index.sha256 == hashlib.sha256(src).hexdigest()
    assert index.size == len(src)
    assert index.line_count == 2
    assert not index.has_parse_errors


def test_empty_file():
    for language in SourceLanguage:
        index = extract_file("e", b"", language)
        assert index.line_count == 0
        assert index.size == 0
        assert index.symbols == index.imports == index.calls == []
        assert not index.has_parse_errors


def test_line_count_without_trailing_newline():
    assert extract_file("a.py", b"x = 1\ny = 2", PY).line_count == 2


def test_crlf_and_bom():
    src = b"\xef\xbb\xbfimport os\r\n\r\ndef f():\r\n    os.system('ls')\r\n"
    index = extract_file("a.py", src, PY)
    assert index.line_count == 4
    assert [i.module for i in index.imports] == ["os"]
    assert index.symbols[0].span.start_line == 3
    assert index.calls[0].line == 4
    assert index.calls[0].literal_args == ["ls"]


def test_non_utf8_bytes():
    src = b"def f():\n    g('\xff\xfe caf\xe9')\n"
    index = extract_file("a.py", src, PY)
    assert index.symbols[0].name == "f"
    assert index.calls[0].callee == "g"
    assert "\ufffd" in index.calls[0].literal_args[0]


# --- python symbols --------------------------------------------------------------------


def test_python_symbols_nested_and_methods():
    index = _py(
        "class Outer:\n"
        "    class Inner:\n"
        "        def m(self):\n"
        "            pass\n"
        "    async def run(self):\n"
        "        def helper():\n"
        "            pass\n"
        "def outer():\n"
        "    def inner():\n"
        "        pass\n"
    )
    syms = _syms(index)
    assert list(syms) == [
        "app/m.py::Outer",
        "app/m.py::Outer.Inner",
        "app/m.py::Outer.Inner.m",
        "app/m.py::Outer.run",
        "app/m.py::Outer.run.helper",
        "app/m.py::outer",
        "app/m.py::outer.inner",
    ]
    assert syms["app/m.py::Outer"].kind is SymbolKind.CLASS
    assert syms["app/m.py::Outer.Inner"].kind is SymbolKind.CLASS
    assert syms["app/m.py::Outer.Inner"].parent_id == "app/m.py::Outer"
    assert syms["app/m.py::Outer.Inner.m"].kind is SymbolKind.METHOD
    assert syms["app/m.py::Outer.run"].kind is SymbolKind.METHOD
    assert syms["app/m.py::Outer.run.helper"].kind is SymbolKind.FUNCTION
    assert syms["app/m.py::Outer.run.helper"].parent_id == "app/m.py::Outer.run"
    assert syms["app/m.py::outer"].parent_id is None
    assert syms["app/m.py::outer"].span.start_line == 8
    assert syms["app/m.py::outer"].span.end_line == 10
    assert syms["app/m.py::outer.inner"].qualified_name == "outer.inner"
    assert all(s.exported is None for s in index.symbols)
    assert all(s.path == "app/m.py" for s in index.symbols)


def test_python_decorators():
    index = _py(
        "@app.route(\n"
        '    "/users",   methods=["POST"])\n'
        "@login_required\n"
        "def create():\n"
        "    pass\n"
        "@dataclass\n"
        "class C:\n"
        "    @property\n"
        "    def p(self): return 1\n"
    )
    syms = _syms(index)
    create = syms["app/m.py::create"]
    assert create.decorators == ['app.route( "/users", methods=["POST"])', "login_required"]
    assert create.span.start_line == 1
    assert create.span.end_line == 5
    assert syms["app/m.py::C"].decorators == ["dataclass"]
    assert syms["app/m.py::C"].span.start_line == 6
    assert syms["app/m.py::C.p"].decorators == ["property"]
    assert syms["app/m.py::C.p"].kind is SymbolKind.METHOD


def test_python_decorator_simple_call():
    index = _py('@app.route("/users", methods=["POST"])\ndef f(): pass\n')
    assert index.symbols[0].decorators == ['app.route("/users", methods=["POST"])']


def test_python_duplicate_ids():
    index = _py(
        "def f(): pass\n\n\ndef f(): pass\ndef f(): pass\nclass A:\n    def m(self): pass\n    def m(self): pass\n"
    )
    assert [s.id for s in index.symbols] == [
        "app/m.py::f",
        "app/m.py::f@4",
        "app/m.py::f@5",
        "app/m.py::A",
        "app/m.py::A.m",
        "app/m.py::A.m@8",
    ]
    assert index.symbols[1].qualified_name == "f"


def test_duplicate_ids_same_line():
    index = _js("function f(){} function f(){} function f(){}")
    assert [s.id for s in index.symbols] == ["src/m.js::f", "src/m.js::f@1", "src/m.js::f@1.2"]


# --- python imports --------------------------------------------------------------------


def test_python_imports():
    index = _py(
        "import a.b\n"
        "import a.b as c\n"
        "import x, y\n"
        "from a.b import c, d as e\n"
        "from .models import X\n"
        "from .. import x\n"
        "from m import *\n"
        "from . import (p,\n    q)\n"
        "from __future__ import annotations\n"
        "def f():\n"
        "    import json\n"
    )
    refs = [(i.line, i.module, i.style, i.level, _names(i), i.module_alias) for i in index.imports]
    assert refs == [
        (1, "a.b", ImportStyle.IMPORT, 0, [], None),
        (2, "a.b", ImportStyle.IMPORT, 0, [], "c"),
        (3, "x", ImportStyle.IMPORT, 0, [], None),
        (3, "y", ImportStyle.IMPORT, 0, [], None),
        (4, "a.b", ImportStyle.FROM, 0, [("c", None), ("d", "e")], None),
        (5, "models", ImportStyle.FROM, 1, [("X", None)], None),
        (6, "", ImportStyle.FROM, 2, [("x", None)], None),
        (7, "m", ImportStyle.FROM, 0, [("*", None)], None),
        (8, "", ImportStyle.FROM, 1, [("p", None), ("q", None)], None),
        (10, "__future__", ImportStyle.FROM, 0, [("annotations", None)], None),
        (12, "json", ImportStyle.IMPORT, 0, [], None),
    ]
    assert all(i.path == "app/m.py" for i in index.imports)
    assert index.calls == []


def test_python_dynamic_imports():
    index = _py(
        "import importlib\n"
        "mod = importlib.import_module('plugins.x')\n"
        "__import__(\"os\").system('id')\n"
        "importlib.import_module(name)\n"
        "importlib.import_module('.sub', 'pkg')\n"
    )
    dyn = [i for i in index.imports if i.style is ImportStyle.DYNAMIC]
    assert [(i.module, i.module_alias, i.level, i.line) for i in dyn] == [
        ("plugins.x", "mod", 0, 2),
        ("os", None, 0, 3),
        ("sub", None, 1, 5),
    ]
    callees = [c.callee for c in index.calls]
    # Literal dynamic imports are not calls; non-literal ones stay calls.
    assert callees == ["__import__().system", "importlib.import_module"]


# --- python calls ----------------------------------------------------------------------


def test_python_callee_normalization():
    index = _py(
        "requests.get(u).json()\n"
        "a[0].b()\n"
        "self.save()\n"
        "(lambda: 1)()\n"
        "super().x()\n"
        "eval(s)\n"
        "(a or b).c()\n"
    )
    assert [c.callee for c in index.calls] == [
        "requests.get().json",
        "requests.get",
        "a[].b",
        "self.save",
        "<expr>",
        "super().x",
        "super",
        "eval",
        "<expr>.c",
    ]


def test_python_caller_attribution():
    index = _py(
        "setup()\n"
        "@deco(x())\n"
        "def f(a=default()):\n"
        "    g()\n"
        "    def h():\n"
        "        k()\n"
        "class C:\n"
        "    registry = register()\n"
        "    def m(self):\n"
        "        self.n()\n"
    )
    callers = [(c.callee, c.caller_id) for c in index.calls]
    assert callers == [
        ("setup", None),
        ("deco", None),
        ("x", None),
        ("default", "app/m.py::f"),
        ("g", "app/m.py::f"),
        ("k", "app/m.py::f.h"),
        ("register", "app/m.py::C"),
        ("self.n", "app/m.py::C.m"),
    ]


def test_python_literal_args():
    long = "x" * 300
    index = _py(
        f"f('a', 1, b'raw', 'skipped-4th')\n"
        f"g(x, \"y\", key='kw')\n"
        f"h(f'{{v}}', 'p' 'q', r'\\d')\n"
        f"i('{long}')\n"
        f"j(*args, 'z')\n"
        f"k(f'plain')\n"
        f"m('a' f'{{v}}')\n"
    )
    args = [c.literal_args for c in index.calls]
    assert args[0] == ["a", "raw"]
    assert args[1] == ["y"]
    assert args[2] == ["pq", "\\d"]
    assert args[3] == ["x" * 100]
    assert args[4] == ["z"]
    assert args[5] == ["plain"]
    assert args[6] == []


# --- JS / TS symbols -------------------------------------------------------------------


def test_js_symbols_and_exports():
    index = _js(
        "function plain() { function nested() {} }\n"
        "function* gen() {}\n"
        "export function exp() {}\n"
        "export default function () {}\n"
        "const arrow = async (x) => x;\n"
        "export const fe = function () {}, notFn = 3;\n"
        "let anon = class {};\n"
        "class Animal {\n"
        "  constructor() {}\n"
        "  get name() { return 1 }\n"
        "  set name(v) {}\n"
        "  static create() {}\n"
        "  #secret() {}\n"
        "  handler = () => {};\n"
        "  value = 3;\n"
        "}\n"
        "export class Dog extends Animal { bark() {} }\n"
        "const obj = { notAMethod() {} };\n"
    )
    syms = _syms(index)
    p = "src/m.js::"
    expected = {
        "plain": (SymbolKind.FUNCTION, False, None),
        "plain.nested": (SymbolKind.FUNCTION, False, p + "plain"),
        "gen": (SymbolKind.FUNCTION, False, None),
        "exp": (SymbolKind.FUNCTION, True, None),
        "default": (SymbolKind.FUNCTION, True, None),
        "arrow": (SymbolKind.FUNCTION, False, None),
        "fe": (SymbolKind.FUNCTION, True, None),
        "anon": (SymbolKind.CLASS, False, None),
        "Animal": (SymbolKind.CLASS, False, None),
        "Animal.constructor": (SymbolKind.METHOD, False, p + "Animal"),
        "Animal.name": (SymbolKind.METHOD, False, p + "Animal"),
        "Animal.name@11": (SymbolKind.METHOD, False, p + "Animal"),
        "Animal.create": (SymbolKind.METHOD, False, p + "Animal"),
        "Animal.#secret": (SymbolKind.METHOD, False, p + "Animal"),
        "Animal.handler": (SymbolKind.METHOD, False, p + "Animal"),
        "Dog": (SymbolKind.CLASS, True, None),
        "Dog.bark": (SymbolKind.METHOD, True, p + "Dog"),
    }
    assert {
        k.removeprefix(p): (s.kind, s.exported, s.parent_id) for k, s in syms.items()
    } == expected
    assert syms[p + "Animal"].span.start_line == 8
    assert syms[p + "Animal"].span.end_line == 16


def test_js_export_default_class_and_named_default():
    index = _js("export default class {}\n")
    assert [(s.name, s.kind, s.exported) for s in index.symbols] == [
        ("default", SymbolKind.CLASS, True)
    ]
    index = _js("export default function main() {}\nexport default () => 1;\n")
    assert [(s.id, s.exported) for s in index.symbols] == [
        ("src/m.js::main", True),
        ("src/m.js::default", True),
    ]


def test_ts_classes_decorators_and_ignored_types():
    index = _js(
        "interface I { m(): void }\n"
        "type T = { a: string };\n"
        "enum E { A }\n"
        "@Component({\n"
        "  selector: 'app-x',\n"
        "})\n"
        "export class AppComponent {\n"
        "  @Input() name: string;\n"
        "  @HostListener('click', ['$event'])\n"
        "  // comment between\n"
        "  onClick(e: Event): void { this.go(e) }\n"
        "  private field = (a: number): number => a;\n"
        "}\n"
        "export abstract class Base { abstract run(): void; stop() {} }\n"
        "@Injectable()\n"
        "class Service {}\n",
        TS,
        "src/app.ts",
    )
    syms = _syms(index)
    p = "src/app.ts::"
    assert set(syms) == {
        p + "AppComponent",
        p + "AppComponent.onClick",
        p + "AppComponent.field",
        p + "Base",
        p + "Base.stop",
        p + "Service",
    }
    app = syms[p + "AppComponent"]
    assert app.decorators == ["Component({ selector: 'app-x', })"]
    assert app.span.start_line == 4
    assert app.exported is True
    click = syms[p + "AppComponent.onClick"]
    assert click.decorators == ["HostListener('click', ['$event'])"]
    assert click.span.start_line == 9
    assert click.kind is SymbolKind.METHOD
    assert syms[p + "Base"].kind is SymbolKind.CLASS
    assert syms[p + "Base"].exported is True
    assert syms[p + "Service"].decorators == ["Injectable()"]
    assert syms[p + "Service"].exported is False
    assert syms[p + "Service"].span.start_line == 15
    # Decorator calls are attributed to the enclosing scope.
    callers = {c.callee: c.caller_id for c in index.calls}
    assert callers["Component"] is None
    assert callers["HostListener"] == p + "AppComponent"
    assert callers["Injectable"] is None
    assert callers["this.go"] == p + "AppComponent.onClick"


def test_tsx_with_jsx():
    index = _js(
        "import React from 'react';\n"
        "export const App = () => (\n"
        "  <div onClick={() => track('click')}>\n"
        '    <Header title="x" />\n'
        "    {items.map((i) => <Item key={i} />)}\n"
        "  </div>\n"
        ");\n",
        TSX,
        "src/App.tsx",
    )
    assert not index.has_parse_errors
    assert [(s.name, s.exported) for s in index.symbols] == [("App", True)]
    assert [(c.callee, c.caller_id, c.literal_args) for c in index.calls] == [
        ("track", "src/App.tsx::App", ["click"]),
        ("items.map", "src/App.tsx::App", []),
    ]
    assert _names(index.imports[0]) == [("default", "React")]


# --- JS / TS imports -------------------------------------------------------------------


def test_es_imports():
    index = _js(
        'import d, {a, b as c} from "m";\n'
        "import * as ns from 'n';\n"
        'import "side-effect";\n'
        'import def from "./local.js";\n'
        'export {a, b as q} from "e";\n'
        'export * from "s";\n'
        'export * as z from "s2";\n'
        "export { local };\n"
        'import {"string name" as sn} from "w";\n',
        TS,
        "src/m.ts",
    )
    refs = [(i.line, i.module, i.style, _names(i), i.module_alias) for i in index.imports]
    assert refs == [
        (1, "m", ImportStyle.ES, [("default", "d"), ("a", None), ("b", "c")], None),
        (2, "n", ImportStyle.ES, [], "ns"),
        (3, "side-effect", ImportStyle.ES, [], None),
        (4, "./local.js", ImportStyle.ES, [("default", "def")], None),
        (5, "e", ImportStyle.ES, [("a", None), ("b", "q")], None),
        (6, "s", ImportStyle.ES, [("*", None)], None),
        (7, "s2", ImportStyle.ES, [("*", "z")], None),
        (9, "w", ImportStyle.ES, [("string name", "sn")], None),
    ]


def test_ts_type_only_imports_skipped():
    index = _js(
        'import type X from "t1";\n'
        'import type { Y } from "t2";\n'
        'import { type Z, W } from "t3";\n'
        'export type { V } from "t4";\n'
        'export { type U, S } from "t5";\n',
        TS,
        "src/m.ts",
    )
    assert [(i.module, _names(i)) for i in index.imports] == [
        ("t3", [("W", None)]),
        ("t5", [("S", None)]),
    ]


def test_require_and_dynamic_imports():
    index = _js(
        'require("side");\n'
        'const x = require("m1");\n'
        "const {a, b: c, d = 1, e: f = 2, ...rest} = require('m2');\n"
        'const y = require("m3").foo;\n'
        'require("m4").bar;\n'
        'let z; z = require("m5");\n'
        'const lazy = import("m6");\n'
        'async function g() { const mod = await import("m7"); }\n'
        "const t = require(`m8`);\n"
        "require(dynamicName);\n"
        "require(`m${x}`);\n"
        "import(variable);\n",
    )
    refs = [(i.module, i.style, _names(i), i.module_alias) for i in index.imports]
    assert refs == [
        ("side", ImportStyle.REQUIRE, [], None),
        ("m1", ImportStyle.REQUIRE, [], "x"),
        ("m2", ImportStyle.REQUIRE, [("a", None), ("b", "c"), ("d", None), ("e", "f")], None),
        ("m3", ImportStyle.REQUIRE, [("foo", "y")], None),
        ("m4", ImportStyle.REQUIRE, [("bar", None)], None),
        ("m5", ImportStyle.REQUIRE, [], "z"),
        ("m6", ImportStyle.DYNAMIC, [], "lazy"),
        ("m7", ImportStyle.DYNAMIC, [], "mod"),
        ("m8", ImportStyle.REQUIRE, [], "t"),
    ]
    # Non-literal specifiers are not imports but remain visible as calls.
    assert [c.callee for c in index.calls] == ["require", "require", "<expr>"]


def test_ts_import_equals_require():
    index = _js('import fs = require("fs");\n', TS, "src/m.ts")
    assert [(i.module, i.style, i.module_alias) for i in index.imports] == [
        ("fs", ImportStyle.REQUIRE, "fs")
    ]


# --- JS / TS calls ---------------------------------------------------------------------


def test_js_callee_normalization():
    index = _js(
        "requests.get(u).json();\n"
        '$("x").on("click", h);\n'
        "a[0].b();\n"
        "a?.b?.c();\n"
        "this.save();\n"
        "super.method();\n"
        "(function () {})();\n"
        "new Foo.Bar(1);\n"
        "new Baz;\n"
        "new Foo().run();\n"
        "obj!.method();\n"
        "(a as any).b();\n",
        TS,
        "src/m.ts",
    )
    assert [c.callee for c in index.calls] == [
        "requests.get().json",
        "requests.get",
        "$().on",
        "$",
        "a[].b",
        "a.b.c",
        "this.save",
        "super.method",
        "<expr>",
        "Foo.Bar",
        "Baz",
        "Foo().run",
        "Foo",
        "obj.method",
        "<expr>.b",
    ]


def test_js_literal_args_and_lines():
    index = _js(
        "app.get('/api/users', handler);\n"
        'f(`tmpl`, `with ${sub}`, "q\\"s", \'fourth\');\n'
        "g(\n  'multi'\n);\n"
        "h(/* c */ 'x');\n"
    )
    assert [(c.line, c.literal_args) for c in index.calls] == [
        (1, ["/api/users"]),
        (2, ["tmpl", 'q\\"s']),
        (3, ["multi"]),
        (6, ["x"]),
    ]


def test_long_callee_truncated():
    name = "a" * 300
    index = _js(f"{name}.b();\n")
    assert len(index.calls[0].callee) == 200


def test_js_caller_attribution():
    index = _js(
        "init();\n"
        "function outer() { inner(); [1].map(x => cb(x)); }\n"
        "class K { static { boot(); } m() { this.n(); } }\n"
        "const h = () => fetch('/x');\n"
    )
    assert [(c.callee, c.caller_id) for c in index.calls] == [
        ("init", None),
        ("inner", "src/m.js::outer"),
        ("<expr>.map", "src/m.js::outer"),
        ("cb", "src/m.js::outer"),
        ("boot", "src/m.js::K"),
        ("this.n", "src/m.js::K.m"),
        ("fetch", "src/m.js::h"),
    ]


# --- robustness ------------------------------------------------------------------------


def test_python_malformed_partial_results():
    index = _py("import os\ndef ok():\n    os.system('x')\ndef broken(:\n    pass\nclass\n")
    assert index.has_parse_errors
    assert [i.module for i in index.imports] == ["os"]
    assert "app/m.py::ok" in _syms(index)
    assert any(c.callee == "os.system" for c in index.calls)


def test_js_malformed_partial_results():
    index = _js("import x from 'm';\nfunction ok() { go(); }\nclass { m( { new ( } export {\n")
    assert index.has_parse_errors
    assert [i.module for i in index.imports] == ["m"]
    assert "src/m.js::ok" in _syms(index)
    assert any(c.callee == "go" for c in index.calls)


@pytest.mark.parametrize("language", list(SourceLanguage))
def test_garbage_never_raises(language):
    rng = random.Random(1234)  # noqa: S311 - deterministic fuzz input
    samples = [
        b"\x00\xff" * 100,
        b"(" * 3000,
        b"[" * 3000,
        b"@" * 500,
        b"a." * 5000 + b"b()",
        b"import from require( export { def class",
        bytes(rng.randrange(256) for _ in range(3000)),
        os.urandom(1000),
    ]
    for src in samples:
        index = extract_file("g", src, language)
        assert index.size == len(src)


@pytest.mark.parametrize("language", list(SourceLanguage))
def test_deep_call_chain_bounded(language):
    src = b"a()" + b".b()" * 5000
    start = time.perf_counter()
    index = extract_file("deep", src, language)
    assert time.perf_counter() - start < 5
    assert len(index.calls) == 5001
    assert all(len(c.callee) <= 200 for c in index.calls)


def test_large_generated_python_file_is_fast():
    src = "".join(f"def f{i}(x):\n    return g(x, 'a{i}')\n" for i in range(2000)).encode()
    start = time.perf_counter()
    index = extract_file("big.py", src, PY)
    assert time.perf_counter() - start < 3
    assert len(index.symbols) == 2000
    assert len(index.calls) == 2000
    assert index.calls[-1].literal_args == ["a1999"]


def test_large_generated_ts_file_is_fast():
    src = "".join(
        f"export function f{i}(x: number) {{ return g(x, 'a'); }}\n" for i in range(2000)
    ).encode()
    start = time.perf_counter()
    index = extract_file("big.ts", src, TS)
    assert time.perf_counter() - start < 3
    assert len(index.symbols) == 2000
    assert all(s.exported for s in index.symbols)


def test_imported_name_local_name():
    index = _js('import {a as b, c} from "m";\n')
    assert [n.local_name for n in index.imports[0].names] == ["b", "c"]
    assert index.imports[0].names[1] == ImportedName(name="c")

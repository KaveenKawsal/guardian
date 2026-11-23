"""Per-file extraction of symbols, imports and call sites.

The parsed code is untrusted: it is only ever walked as a syntax tree, never executed. The
walk is iterative (no recursion limit on deeply nested input) and visits each node once;
every per-node helper does bounded work, so extraction stays linear in the file size.
"""

import hashlib
from collections.abc import Callable
from dataclasses import dataclass

from tree_sitter import Node

from guardian.core.models import (
    CallRef,
    FileIndex,
    ImportedName,
    ImportRef,
    ImportStyle,
    SourceLanguage,
    Span,
    Symbol,
    SymbolKind,
)
from guardian.indexing.tree_sitter import get_parser

MAX_CALLEE_CHARS = 200
MAX_LITERAL_CHARS = 100
MAX_LITERAL_ARGS = 3
MAX_DECORATOR_CHARS = 1000
_MAX_CHAIN = 64  # callee chain links examined; deeper chains get an "<expr>" base
_EXPR = "<expr>"
_PY_DYNAMIC_IMPORTS = frozenset({"importlib.import_module", "__import__"})
_JS_FUNCTION_VALUES = frozenset(
    {"arrow_function", "function_expression", "function", "generator_function"}
)
_JS_CLASS_NODES = frozenset({"class_declaration", "abstract_class_declaration", "class"})
_JS_FIELD_NODES = frozenset({"public_field_definition", "field_definition"})


@dataclass(frozen=True, slots=True)
class _Scope:
    id: str
    qualname: str
    kind: SymbolKind
    exported: bool | None
    node: Node


def _text(node: Node | None, limit: int | None = None) -> str:
    if node is None:
        return ""
    raw = node.text or b""
    if limit is not None:
        raw = raw[: limit * 4]  # a UTF-8 character is at most 4 bytes
    value = raw.decode("utf-8", errors="replace")
    return value if limit is None else value[:limit]


def _collapse(value: str) -> str:
    return " ".join(value.split())


def _line(node: Node) -> int:
    return node.start_point[0] + 1


def _decorator_text(node: Node) -> str:
    value = _collapse(_text(node, MAX_DECORATOR_CHARS))
    return value.removeprefix("@").strip()


def _between(node: Node, start: int, end: int) -> str:
    """Up to MAX_LITERAL_CHARS of source between absolute byte offsets ``start`` and ``end``."""
    base = node.start_byte
    raw = (node.text or b"")[start - base : min(end - base, start - base + MAX_LITERAL_CHARS * 4)]
    return raw.decode("utf-8", errors="replace")[:MAX_LITERAL_CHARS]


def _py_string(node: Node) -> str | None:
    if node.type == "concatenated_string":
        parts = [_py_string(child) for child in node.named_children]
        if any(part is None for part in parts):
            return None
        return "".join(p for p in parts if p is not None)[:MAX_LITERAL_CHARS]
    if node.type != "string":
        return None
    start = end = None
    for child in node.children:
        if child.type == "interpolation":
            return None
        if child.type == "string_start":
            start = child.end_byte
        elif child.type == "string_end":
            end = child.start_byte
    if start is None or end is None or end < start:
        return None
    return _between(node, start, end)


def _js_string(node: Node) -> str | None:
    if node.type == "template_string":
        if any(child.type == "template_substitution" for child in node.named_children):
            return None
    elif node.type != "string":
        return None
    if node.end_byte - node.start_byte < 2:  # noqa: PLR2004 - two quote characters
        return None
    return _between(node, node.start_byte + 1, node.end_byte - 1)


_PY_MEMBER = {"attribute": ("object", "attribute")}
_JS_MEMBER = {"member_expression": ("object", "property")}
_PY_LINKS = {"call": "function", "subscript": "value"}
_JS_LINKS = {
    "call_expression": "function",
    "new_expression": "constructor",
    "subscript_expression": "object",
}
_LINK_SUFFIX = {
    "call": "()",
    "call_expression": "()",
    "new_expression": "()",
    "subscript": "[]",
    "subscript_expression": "[]",
}
_PY_NAMES = frozenset({"identifier"})
_JS_NAMES = frozenset({"identifier", "this", "super"})


class _Extractor:
    def __init__(self, path: str, language: SourceLanguage) -> None:
        self.path = path
        self.python = language is SourceLanguage.PYTHON
        self.symbols: list[Symbol] = []
        self.imports: list[ImportRef] = []
        self.calls: list[CallRef] = []
        self._ids: set[str] = set()
        self._members = _PY_MEMBER if self.python else _JS_MEMBER
        self._links = _PY_LINKS if self.python else _JS_LINKS
        self._names = _PY_NAMES if self.python else _JS_NAMES
        self._string = _py_string if self.python else _js_string
        self._handlers: dict[str, Callable[[Node, _Scope | None], _Scope | None]] = (
            self._python_handlers() if self.python else self._js_handlers()
        )

    def _python_handlers(self) -> dict[str, Callable[[Node, _Scope | None], _Scope | None]]:
        return {
            "class_definition": self._py_definition,
            "function_definition": self._py_definition,
            "import_statement": self._py_import,
            "import_from_statement": self._py_import_from,
            "future_import_statement": self._py_import_from,
            "call": self._py_call,
        }

    def _js_handlers(self) -> dict[str, Callable[[Node, _Scope | None], _Scope | None]]:
        handlers: dict[str, Callable[[Node, _Scope | None], _Scope | None]] = {
            "function_declaration": self._js_function,
            "generator_function_declaration": self._js_function,
            "method_definition": self._js_method,
            "variable_declarator": self._js_variable,
            "function_expression": self._js_default_export,
            "arrow_function": self._js_default_export,
            "import_statement": self._js_import,
            "export_statement": self._js_reexport,
            "call_expression": self._js_call,
            "new_expression": self._js_call,
        }
        handlers.update(dict.fromkeys(_JS_CLASS_NODES, self._js_class))
        handlers.update(dict.fromkeys(_JS_FIELD_NODES, self._js_method))
        return handlers

    # --- walk ---------------------------------------------------------------------------

    def walk(self, root: Node) -> None:
        stack: list[tuple[Node, _Scope | None]] = [(root, None)]
        while stack:
            node, scope = stack.pop()
            handler = self._handlers.get(node.type)
            inner = handler(node, scope) if handler is not None else scope
            # Decorators belong to the enclosing scope, not to the decorated class/method.
            stack.extend(
                (child, scope if child.type == "decorator" else inner)
                for child in reversed(node.named_children)
            )

    # --- symbols ------------------------------------------------------------------------

    def _add_symbol(  # noqa: PLR0913 - mirrors Symbol fields
        self,
        name: str,
        kind: SymbolKind,
        node: Node,
        scope: _Scope | None,
        *,
        start: Node | None = None,
        decorators: list[str] | None = None,
        exported: bool | None = None,
    ) -> _Scope:
        start = start or node
        qualname = f"{scope.qualname}.{name}" if scope is not None else name
        start_line = _line(start)
        symbol_id = f"{self.path}::{qualname}"
        if symbol_id in self._ids:
            base = f"{symbol_id}@{start_line}"
            symbol_id, counter = base, 1
            while symbol_id in self._ids:
                counter += 1
                symbol_id = f"{base}.{counter}"
        self._ids.add(symbol_id)
        self.symbols.append(
            Symbol(
                id=symbol_id,
                name=name,
                qualified_name=qualname,
                kind=kind,
                path=self.path,
                span=Span(start_line=start_line, end_line=max(node.end_point[0] + 1, start_line)),
                parent_id=scope.id if scope is not None else None,
                decorators=decorators or [],
                exported=exported,
            )
        )
        return _Scope(symbol_id, qualname, kind, exported, node)

    def _py_definition(self, node: Node, scope: _Scope | None) -> _Scope | None:
        name = _text(node.child_by_field_name("name"))
        if not name:
            return scope
        if node.type == "class_definition":
            kind = SymbolKind.CLASS
        elif scope is not None and scope.kind is SymbolKind.CLASS:
            kind = SymbolKind.METHOD
        else:
            kind = SymbolKind.FUNCTION
        start, decorators = node, []
        parent = node.parent
        if parent is not None and parent.type == "decorated_definition":
            start = parent
            decorators = [
                _decorator_text(d) for d in parent.named_children if d.type == "decorator"
            ]
        return self._add_symbol(name, kind, node, scope, start=start, decorators=decorators)

    def _js_decorated(self, node: Node, holder: Node | None) -> tuple[Node, list[str]]:
        """First node of the symbol's span and its decorators (own children + ``holder``'s)."""
        found = [c for c in node.named_children if c.type == "decorator"]
        if holder is not None:
            found = [c for c in holder.named_children if c.type == "decorator"] + found
        start = min([node, *found], key=lambda n: n.start_byte)
        return start, [_decorator_text(d) for d in found]

    def _js_function(self, node: Node, scope: _Scope | None) -> _Scope | None:
        name = _text(node.child_by_field_name("name"))
        if not name:
            return scope
        exported = _js_export_parent(node) is not None
        return self._add_symbol(name, SymbolKind.FUNCTION, node, scope, exported=exported)

    def _js_class(self, node: Node, scope: _Scope | None) -> _Scope | None:
        export = _js_export_parent(node)
        name = _text(node.child_by_field_name("name"))
        if not name and node.type == "class" and _is_default_export(export):
            name = "default"
        if not name:
            return scope
        start, decorators = self._js_decorated(node, export)
        exported = export is not None
        return self._add_symbol(
            name,
            SymbolKind.CLASS,
            node,
            scope,
            start=start,
            decorators=decorators,
            exported=exported,
        )

    def _js_method(self, node: Node, scope: _Scope | None) -> _Scope | None:
        body = node.parent
        if scope is None or body is None or body.type != "class_body" or body.parent != scope.node:
            return scope
        if node.type in _JS_FIELD_NODES:
            value = node.child_by_field_name("value")
            if value is None or value.type not in _JS_FUNCTION_VALUES:
                return scope
            name_node = node.child_by_field_name("name") or node.child_by_field_name("property")
        else:
            name_node = node.child_by_field_name("name")
        name = _collapse(_text(name_node, MAX_CALLEE_CHARS))
        if not name:
            return scope
        found = [c for c in node.named_children if c.type == "decorator"]
        sibling = node.prev_named_sibling
        while sibling is not None and sibling.type in {"decorator", "comment"}:
            if sibling.type == "decorator":
                found.insert(0, sibling)
            sibling = sibling.prev_named_sibling
        start = min([node, *found], key=lambda n: n.start_byte)
        decorators = [_decorator_text(d) for d in found]
        return self._add_symbol(
            name,
            SymbolKind.METHOD,
            node,
            scope,
            start=start,
            decorators=decorators,
            exported=scope.exported,
        )

    def _js_variable(self, node: Node, scope: _Scope | None) -> _Scope | None:
        name_node = node.child_by_field_name("name")
        value = node.child_by_field_name("value")
        if name_node is None or name_node.type != "identifier" or value is None:
            return scope
        if value.type in _JS_FUNCTION_VALUES:
            kind = SymbolKind.FUNCTION
        elif value.type == "class" and value.child_by_field_name("name") is None:
            kind = SymbolKind.CLASS
        else:
            return scope
        declaration = node.parent
        exported = declaration is not None and _js_export_parent(declaration) is not None
        return self._add_symbol(_text(name_node), kind, node, scope, exported=exported)

    def _js_default_export(self, node: Node, scope: _Scope | None) -> _Scope | None:
        if not _is_default_export(_js_export_parent(node)):
            return scope
        name = _text(node.child_by_field_name("name")) or "default"
        return self._add_symbol(name, SymbolKind.FUNCTION, node, scope, exported=True)

    # --- imports ------------------------------------------------------------------------

    def _add_import(  # noqa: PLR0913 - mirrors ImportRef fields
        self,
        node: Node,
        module: str,
        style: ImportStyle,
        *,
        names: list[ImportedName] | None = None,
        alias: str | None = None,
        level: int = 0,
    ) -> None:
        self.imports.append(
            ImportRef(
                path=self.path,
                line=_line(node),
                module=module,
                style=style,
                level=level,
                names=names or [],
                module_alias=alias,
            )
        )

    def _py_import(self, node: Node, scope: _Scope | None) -> _Scope | None:
        for item in node.children_by_field_name("name"):
            if item.type == "aliased_import":
                module = _dotted(item.child_by_field_name("name"))
                alias = _text(item.child_by_field_name("alias")) or None
            else:
                module, alias = _dotted(item), None
            if module:
                self._add_import(node, module, ImportStyle.IMPORT, alias=alias)
        return scope

    def _py_import_from(self, node: Node, scope: _Scope | None) -> _Scope | None:
        module, level = "__future__", 0
        if node.type == "import_from_statement":
            module_node = node.child_by_field_name("module_name")
            if module_node is None:
                return scope
            module, level = _py_module(module_node)
        names: list[ImportedName] = []
        if any(child.type == "wildcard_import" for child in node.named_children):
            names.append(ImportedName(name="*"))
        for item in node.children_by_field_name("name"):
            if item.type == "aliased_import":
                name = _dotted(item.child_by_field_name("name"))
                alias = _text(item.child_by_field_name("alias")) or None
            else:
                name, alias = _dotted(item), None
            if name:
                names.append(ImportedName(name=name, alias=alias))
        self._add_import(node, module, ImportStyle.FROM, names=names, level=level)
        return scope

    def _js_import(self, node: Node, scope: _Scope | None) -> _Scope | None:
        if _has_token(node, "type", "typeof"):
            return scope
        names: list[ImportedName] = []
        alias = None
        for child in node.named_children:
            if child.type == "import_require_clause":
                module = _js_string(child.child_by_field_name("source") or child)
                ident = next((c for c in child.named_children if c.type == "identifier"), None)
                if module is not None:
                    self._add_import(node, module, ImportStyle.REQUIRE, alias=_text(ident) or None)
                return scope
            if child.type == "import_clause":
                alias = _js_import_clause(child, names)
        source = node.child_by_field_name("source")
        module = _js_string(source) if source is not None else None
        if module is not None:
            self._add_import(node, module, ImportStyle.ES, names=names, alias=alias)
        return scope

    def _js_reexport(self, node: Node, scope: _Scope | None) -> _Scope | None:
        source = node.child_by_field_name("source")
        if source is None or _has_token(node, "type"):
            return scope
        module = _js_string(source)
        if module is None:
            return scope
        names: list[ImportedName] = []
        for child in node.children:
            if child.type == "*":
                names.append(ImportedName(name="*"))
            elif child.type == "namespace_export":
                ident = next((c for c in child.named_children if c.type != "comment"), None)
                names.append(ImportedName(name="*", alias=_text(ident) or None))
            elif child.type == "export_clause":
                names.extend(_js_specifiers(child, "export_specifier"))
        self._add_import(node, module, ImportStyle.ES, names=names)
        return scope

    # --- calls --------------------------------------------------------------------------

    def _positional_args(self, node: Node) -> list[Node]:
        args = node.child_by_field_name("arguments")
        if args is None:
            return []
        skip = {"comment", "keyword_argument", "dictionary_splat"}
        result: list[Node] = []
        for child in args.named_children:
            if child.type not in skip:
                result.append(child)
                if len(result) == MAX_LITERAL_ARGS:
                    break
        return result

    def _add_call(self, node: Node, callee: str, scope: _Scope | None, args: list[Node]) -> None:
        literals = [value for value in map(self._string, args) if value is not None]
        self.calls.append(
            CallRef(
                path=self.path,
                line=_line(node),
                callee=callee,
                caller_id=scope.id if scope is not None else None,
                literal_args=literals,
            )
        )

    def _py_call(self, node: Node, scope: _Scope | None) -> _Scope | None:
        callee = self._callee(node.child_by_field_name("function"))
        args = self._positional_args(node)
        if callee in _PY_DYNAMIC_IMPORTS and args:
            module = _py_string(args[0])
            if module is not None:
                stripped = module.lstrip(".")
                parent = node.parent
                alias = None
                if parent is not None and parent.type == "assignment":
                    left = parent.child_by_field_name("left")
                    if left is not None and left.type == "identifier":
                        alias = _text(left)
                level = len(module) - len(stripped)
                self._add_import(node, stripped, ImportStyle.DYNAMIC, alias=alias, level=level)
                return scope
        self._add_call(node, callee, scope, args)
        return scope

    def _js_call(self, node: Node, scope: _Scope | None) -> _Scope | None:
        field = "constructor" if node.type == "new_expression" else "function"
        function = node.child_by_field_name(field)
        args = self._positional_args(node)
        if node.type == "call_expression" and function is not None and args:
            dynamic = function.type == "import"
            if dynamic or (function.type == "identifier" and _text(function) == "require"):
                module = _js_string(args[0])
                if module is not None:
                    alias, names = _js_binding(node)
                    style = ImportStyle.DYNAMIC if dynamic else ImportStyle.REQUIRE
                    self._add_import(node, module, style, names=names, alias=alias)
                    return scope
        self._add_call(node, self._callee(function), scope, args)
        return scope

    def _callee(self, node: Node | None) -> str:
        parts: list[str] = []
        base = _EXPR
        current = node
        for _ in range(_MAX_CHAIN):
            if current is None:
                break
            kind = current.type
            if kind in self._names:
                base = _text(current, MAX_CALLEE_CHARS)
                break
            if kind in self._members:
                object_field, member_field = self._members[kind]
                parts.append("." + _collapse(_text(current.child_by_field_name(member_field))))
                current = current.child_by_field_name(object_field)
            elif kind in self._links:
                parts.append(_LINK_SUFFIX[kind])
                current = current.child_by_field_name(self._links[kind])
            elif kind == "non_null_expression" and current.named_children:
                current = current.named_children[0]
            else:
                break
        return (base + "".join(reversed(parts)))[:MAX_CALLEE_CHARS]


def _dotted(node: Node | None) -> str:
    return "".join(_text(node).split())


def _py_module(node: Node) -> tuple[str, int]:
    if node.type != "relative_import":
        return _dotted(node), 0
    level, module = 0, ""
    for child in node.named_children:
        if child.type == "import_prefix":
            level = _text(child).count(".")
        elif child.type == "dotted_name":
            module = _dotted(child)
    return module, level


def _has_token(node: Node, *tokens: str) -> bool:
    return any(child.type in tokens and not child.is_named for child in node.children)


def _js_specifiers(node: Node, kind: str) -> list[ImportedName]:
    names: list[ImportedName] = []
    for spec in node.named_children:
        if spec.type != kind or _has_token(spec, "type", "typeof"):
            continue
        name = _js_name(spec.child_by_field_name("name"))
        if name:
            alias = _js_name(spec.child_by_field_name("alias")) or None
            names.append(ImportedName(name=name, alias=alias))
    return names


def _js_name(node: Node | None) -> str:
    """An identifier, or the value of a string module-export name (``import {"a-b" as c}``)."""
    if node is None:
        return ""
    if node.type == "string":
        return _js_string(node) or ""
    return _text(node, MAX_CALLEE_CHARS)


def _js_import_clause(clause: Node, names: list[ImportedName]) -> str | None:
    """Append the clause's bound names to ``names``; return the namespace alias if any."""
    alias = None
    for part in clause.named_children:
        if part.type == "identifier":
            names.append(ImportedName(name="default", alias=_text(part)))
        elif part.type == "namespace_import":
            ident = next((c for c in part.named_children if c.type == "identifier"), None)
            alias = _text(ident) or None
        elif part.type == "named_imports":
            names.extend(_js_specifiers(part, "import_specifier"))
    return alias


def _js_binding(call: Node) -> tuple[str | None, list[ImportedName]]:
    """What a ``require(...)``/``import(...)`` result is bound to: (module alias, names)."""
    node, parent = call, call.parent
    if parent is not None and parent.type == "await_expression":
        node, parent = parent, parent.parent
    member = None
    if (
        parent is not None
        and parent.type == "member_expression"
        and parent.child_by_field_name("object") == node
    ):
        member = _text(parent.child_by_field_name("property"), MAX_CALLEE_CHARS) or None
        node, parent = parent, parent.parent
    target = None
    if parent is not None and parent.type == "variable_declarator":
        target = parent.child_by_field_name("name")
    elif parent is not None and parent.type == "assignment_expression":
        target = parent.child_by_field_name("left")
    ident = _text(target) if target is not None and target.type == "identifier" else None
    if member is not None:
        return None, [ImportedName(name=member, alias=ident)]
    if target is not None and target.type == "object_pattern":
        return None, _js_object_pattern(target)
    return ident, []


def _js_object_pattern(pattern: Node) -> list[ImportedName]:
    names: list[ImportedName] = []
    for item in pattern.named_children:
        if item.type == "object_assignment_pattern":
            item = item.child_by_field_name("left") or item  # noqa: PLW2901 - unwrap default
        if item.type == "shorthand_property_identifier_pattern":
            names.append(ImportedName(name=_text(item)))
        elif item.type == "pair_pattern":
            key = _js_name(item.child_by_field_name("key"))
            value = item.child_by_field_name("value")
            if value is not None and value.type == "assignment_pattern":
                value = value.child_by_field_name("left")
            alias = _text(value) if value is not None and value.type == "identifier" else None
            if key:
                names.append(ImportedName(name=key, alias=alias))
    return names


def _js_export_parent(node: Node) -> Node | None:
    parent = node.parent
    return parent if parent is not None and parent.type == "export_statement" else None


def _is_default_export(export: Node | None) -> bool:
    return export is not None and _has_token(export, "default")


def _line_count(source: bytes) -> int:
    if not source:
        return 0
    return source.count(b"\n") + (0 if source.endswith(b"\n") else 1)


def extract_file(path: str, source: bytes, language: SourceLanguage) -> FileIndex:
    """Parse ``source`` (the file at repository-relative ``path``) and return its FileIndex.

    Pure function: no filesystem access, no execution of the parsed code. Never raises on
    malformed source; sets ``has_parse_errors`` and extracts what the error-tolerant tree
    still contains.
    """
    tree = get_parser(language).parse(source)
    extractor = _Extractor(path, language)
    extractor.walk(tree.root_node)
    return FileIndex(
        path=path,
        language=language,
        sha256=hashlib.sha256(source).hexdigest(),
        size=len(source),
        line_count=_line_count(source),
        symbols=extractor.symbols,
        imports=extractor.imports,
        calls=extractor.calls,
        has_parse_errors=tree.root_node.has_error,
    )

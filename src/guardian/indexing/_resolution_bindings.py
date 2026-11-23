"""Per-file name bindings built from resolved imports and top-level symbols."""

import re
from collections import deque
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field

from guardian.core.models import (
    FileIndex,
    ImportRef,
    ImportTarget,
    ResolvedImport,
    SourceLanguage,
    Symbol,
)
from guardian.indexing._resolution_js import package_name

_Locator = Callable[[int], tuple[str | None, tuple[str, ...]]]
_SUFFIX_RE = re.compile(r"@\d+")
_JS_EXTENSIONS = re.compile(r"\.(?:[cm]?[jt]sx?|json)$")


@dataclass(frozen=True)
class Binding:
    """What a local name refers to: an import (module or member) or a local symbol."""

    resolved: ResolvedImport | None = None
    symbol: Symbol | None = None
    loc: str | None = None
    """Internal target: Python module key ('pkg/mod', no suffix) or JS file path."""
    member: tuple[str, ...] = ()


@dataclass
class FileBindings:
    names: dict[str, Binding] = field(default_factory=dict)
    star_locs: list[str] = field(default_factory=list)


def python_module_key(target_path: str) -> str:
    if target_path == "__init__.py":
        return ""
    if target_path.endswith("/__init__.py"):
        return target_path[: -len("/__init__.py")]
    return target_path.removesuffix(".pyi").removesuffix(".py")


class Context:
    """Global lookups: files by path, symbols by (path, qualified name) and by id."""

    def __init__(self, files: Sequence[FileIndex]) -> None:
        self.files: dict[str, FileIndex] = {}
        self.symbols: dict[str, dict[str, Symbol]] = {}
        self.by_id: dict[str, Symbol] = {}
        for file_index in files:
            self.files.setdefault(file_index.path, file_index)
            table = self.symbols.setdefault(file_index.path, {})
            for symbol in file_index.symbols:
                self.by_id.setdefault(symbol.id, symbol)
                table.setdefault(symbol.qualified_name, symbol)
            for symbol in file_index.symbols:
                table.setdefault(_SUFFIX_RE.sub("", symbol.qualified_name), symbol)

    def lookup(self, path: str, qualified_name: str) -> Symbol | None:
        table = self.symbols.get(path)
        return table.get(qualified_name) if table else None

    def module_file(self, key: str) -> str | None:
        candidates = (f"{key}.py", f"{key}/__init__.py") if key else ("__init__.py",)
        return next((c for c in candidates if c in self.files), None)


def match_imports(
    files: Sequence[FileIndex], imports: Iterable[ResolvedImport]
) -> dict[int, ResolvedImport]:
    """Pair each ImportRef (by ``id``) with its ResolvedImport via (path, line, module, style)."""
    queues: dict[tuple[str, int, str, str], deque[ResolvedImport]] = {}
    for resolved in imports:
        key = (resolved.path, resolved.line, resolved.module, str(resolved.style))
        queues.setdefault(key, deque()).append(resolved)
    matched: dict[int, ResolvedImport] = {}
    for file_index in files:
        for ref in file_index.imports:
            queue = queues.get((ref.path, ref.line, ref.module, str(ref.style)))
            if queue:
                matched[id(ref)] = queue.popleft()
    return matched


def build_bindings(file_index: FileIndex, matched: dict[int, ResolvedImport]) -> FileBindings:
    entries: list[tuple[int, int, str, Binding]] = []
    result = FileBindings()
    is_python = file_index.language is SourceLanguage.PYTHON
    for ref in file_index.imports:
        resolved = matched.get(id(ref))
        if resolved is None or resolved.target is ImportTarget.UNRESOLVED:
            continue
        builder = _python_bindings if is_python else _js_bindings
        for name, binding in builder(ref, resolved, result):
            entries.append((ref.line, len(entries), name, binding))
    for symbol in file_index.symbols:
        if symbol.parent_id is None:
            entries.append(
                (symbol.span.start_line, len(entries), symbol.name, Binding(symbol=symbol))
            )
    entries.sort(key=lambda entry: (entry[0], entry[1]))
    result.names = {name: binding for _, _, name, binding in entries}
    return result


def _python_bindings(
    ref: ImportRef, resolved: ResolvedImport, result: FileBindings
) -> list[tuple[str, Binding]]:
    parts = [p for p in ref.module.lstrip(".").split(".") if p]
    module_at = _python_locator(parts, resolved)
    out: list[tuple[str, Binding]] = []
    if ref.names:
        loc, prefix = module_at(len(parts))
        for imported in ref.names:
            if imported.name == "*":
                if loc is not None:
                    result.star_locs.append(loc)
                continue
            out.append(
                (imported.local_name, Binding(resolved, None, loc, (*prefix, imported.name)))
            )
        return out
    if ref.module_alias:
        loc, prefix = module_at(len(parts))
        return [(ref.module_alias, Binding(resolved, None, loc, prefix))]
    if parts:
        loc, prefix = module_at(1)
        return [(parts[0], Binding(resolved, None, loc, prefix))]
    return out


def _python_locator(parts: list[str], resolved: ResolvedImport) -> _Locator:
    """Return f(j) -> (internal key of module parts[:j] or None, member prefix)."""
    if resolved.target is not ImportTarget.INTERNAL:
        return lambda j: (None, tuple(parts[1:j]))
    if resolved.target_path is None:
        return lambda _j: (None, ())
    key = python_module_key(resolved.target_path)
    segments = key.split("/") if key else []
    matched = 0
    for k in range(min(len(parts), len(segments)), 0, -1):
        if segments[-k:] == parts[:k]:
            matched = k
            break

    def locate(j: int) -> tuple[str | None, tuple[str, ...]]:
        if j <= matched:
            return "/".join(segments[: len(segments) - (matched - j)]), ()
        return key, tuple(parts[matched:j])

    return locate


def _js_bindings(
    ref: ImportRef, resolved: ResolvedImport, result: FileBindings
) -> list[tuple[str, Binding]]:
    internal = resolved.target is ImportTarget.INTERNAL
    loc = resolved.target_path if internal else None
    prefix = () if internal else _js_subpath(ref.module)
    out: list[tuple[str, Binding]] = []
    if ref.module_alias:
        out.append((ref.module_alias, Binding(resolved, None, loc, prefix)))
    for imported in ref.names:
        if imported.name != "*":
            out.append(
                (imported.local_name, Binding(resolved, None, loc, (*prefix, imported.name)))
            )
        elif imported.alias:
            out.append((imported.alias, Binding(resolved, None, loc, prefix)))
        elif loc is not None:
            result.star_locs.append(loc)
    return out


def _js_subpath(spec: str) -> tuple[str, ...]:
    """Member prefix for package subpaths: 'lodash/fp' -> ('fp',), 'node:fs/promises' -> ..."""
    spec = spec.strip().removeprefix("node:")
    name = package_name(spec)
    if name is None:
        return ()
    rest = _JS_EXTENSIONS.sub("", spec[len(name) :].strip("/"))
    return tuple(p for p in rest.split("/") if p and p not in {".", ".."})

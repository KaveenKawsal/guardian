"""Entry point detection (how execution and requests enter the application).

Pure functions over the extracted index and manifest bytes: nothing here reads the
filesystem or executes repository code. Manifests come from a hostile repository, so
parsing tolerates any malformed or unexpectedly shaped content.
"""

import json
import re
import tomllib
from collections.abc import Collection, Iterator, Mapping, Sequence
from pathlib import PurePosixPath

from guardian.core.models import (
    CallRef,
    EntryPoint,
    EntryPointKind,
    FileIndex,
    ResolvedCall,
    SourceLanguage,
    SymbolKind,
)

MAX_DETAIL_CHARS = 200

_DECORATOR_ROUTE = re.compile(
    r"\.(route|get|post|put|patch|delete|head|options|api_route|websocket)\("
)
_FIRST_STRING_ARG = re.compile(r"""\(\s*[rRbBuU]?(['"])(.*?)\1""")
_ROUTE_METHODS = frozenset(
    {"get", "post", "put", "patch", "delete", "all", "use", "route", "options", "head"}
)
_SERVER_CALLS = frozenset({"uvicorn.run", "app.run", "serve", "waitress.serve"})
_JS_LANGUAGES = frozenset(
    {SourceLanguage.JAVASCRIPT, SourceLanguage.TYPESCRIPT, SourceLanguage.TSX}
)
_FUNCTION_KINDS = frozenset({SymbolKind.FUNCTION, SymbolKind.METHOD})
_TEST_DIRS = frozenset({"test", "tests", "__tests__", "spec", "specs", "cypress", "e2e"})
_TEST_FILE = re.compile(r"(\.(spec|test|e2e|cy)\.[cm]?[jt]sx?$)|(^test_.*\.py$)|(_test\.py$)")


def is_test_path(path: str) -> bool:
    """Test code by directory (test/, __tests__/, cypress/ ...) or file name convention."""
    parts = PurePosixPath(path).parts
    return any(p.lower() in _TEST_DIRS for p in parts[:-1]) or bool(
        _TEST_FILE.search(parts[-1].lower() if parts else "")
    )


def detect_entry_points(
    files: Sequence[FileIndex],
    calls: Sequence[ResolvedCall],
    *,
    main_guard_paths: Collection[str],
    manifests: Mapping[str, bytes],
) -> list[EntryPoint]:
    """Entry points from symbols, calls, ``if __name__ == "__main__"`` files and manifests.

    ``main_guard_paths``: Python files containing a main guard (detected by the indexer while
    it has the source). ``manifests``: repository-relative path -> bytes of each
    package.json / pyproject.toml, already size-limited by the caller. Pure function.
    """
    found = [
        *_dunder_mains(files),
        *(
            EntryPoint(path=p, kind=EntryPointKind.MAIN_GUARD, detail="if __name__ == '__main__'")
            for p in main_guard_paths
        ),
        *_decorator_routes(files),
    ]
    decorator_routes = {(e.path, e.detail) for e in found if e.kind is EntryPointKind.HTTP_ROUTE}
    resolved = {(c.path, c.line, c.callee): c for c in calls}
    for f in files:
        # Test clients call `request(app).get("/api/x")`: these are not server routes.
        if is_test_path(f.path):
            continue
        for call in f.calls:
            entry = _call_entry_point(
                call, f.language, resolved.get((f.path, call.line, call.callee))
            )
            # Python decorators are call sites too: keep the decorator-derived route only.
            if entry and not (
                entry.kind is EntryPointKind.HTTP_ROUTE
                and (entry.path, entry.detail) in decorator_routes
            ):
                found.append(entry)
    for path, data in manifests.items():
        found.extend(_manifest_entry_points(path, data))
    return _dedupe_sorted(found)


def _dedupe_sorted(entries: list[EntryPoint]) -> list[EntryPoint]:
    unique: dict[tuple[str, int, str, str], EntryPoint] = {}
    for e in entries:
        unique.setdefault((e.path, e.line or 0, e.kind.value, e.detail), e)
    return [unique[k] for k in sorted(unique)]


def _detail(text: str) -> str:
    cleaned = "".join(ch if ch.isprintable() else " " for ch in text)
    return cleaned[:MAX_DETAIL_CHARS]


def _dunder_mains(files: Sequence[FileIndex]) -> Iterator[EntryPoint]:
    for f in files:
        if PurePosixPath(f.path).name == "__main__.py":
            yield EntryPoint(path=f.path, kind=EntryPointKind.DUNDER_MAIN, detail="__main__.py")


def _decorator_routes(files: Sequence[FileIndex]) -> Iterator[EntryPoint]:
    for f in files:
        if f.language is not SourceLanguage.PYTHON:
            continue
        for symbol in f.symbols:
            if symbol.kind not in _FUNCTION_KINDS:
                continue
            for decorator in symbol.decorators:
                if detail := route_from_decorator(decorator):
                    yield EntryPoint(
                        path=f.path,
                        line=symbol.span.start_line,
                        kind=EntryPointKind.HTTP_ROUTE,
                        detail=detail,
                        symbol_id=symbol.id,
                    )


def route_from_decorator(decorator: str) -> str | None:
    """'app.get("/users")' -> 'GET /users'; 'bp.route("/x")' -> 'ROUTE /x'; else None."""
    match = _DECORATOR_ROUTE.search(decorator)
    if not match:
        return None
    method = "ROUTE" if match.group(1) == "api_route" else match.group(1).upper()
    arg = _FIRST_STRING_ARG.match(decorator, match.end() - 1)
    return _detail(f"{method} {arg.group(2)}" if arg else method)


def _call_entry_point(
    call: CallRef, language: SourceLanguage, resolved: ResolvedCall | None
) -> EntryPoint | None:
    callee = call.callee.replace(" ", "")
    receiver, _, last = callee.rpartition(".")
    first = call.literal_args[0] if call.literal_args else ""
    if receiver and last in _ROUTE_METHODS and first.startswith("/"):
        return EntryPoint(
            path=call.path,
            line=call.line,
            kind=EntryPointKind.HTTP_ROUTE,
            detail=_detail(f"{last.upper()} {first}"),
            symbol_id=call.caller_id,
        )
    if _is_server_call(callee, receiver, last, language, resolved):
        return EntryPoint(
            path=call.path,
            line=call.line,
            kind=EntryPointKind.SERVER_LISTEN,
            detail=_detail(callee),
            symbol_id=call.caller_id,
        )
    return None


def _is_server_call(
    callee: str,
    receiver: str,
    last: str,
    language: SourceLanguage,
    resolved: ResolvedCall | None,
) -> bool:
    if callee in _SERVER_CALLS:
        return True
    if receiver and last == "listen" and language in _JS_LANGUAGES:
        return True
    # e.g. `from uvicorn import run` ... `run(app)`: the resolver knows the package.
    if resolved and resolved.package and resolved.member:
        return f"{resolved.package}.{resolved.member}" in {"uvicorn.run", "waitress.serve"}
    return False


def _manifest_entry_points(path: str, data: bytes) -> list[EntryPoint]:
    name = PurePosixPath(path).name
    if name == "package.json":
        details = _package_json_details(data)
    elif name == "pyproject.toml":
        details = _pyproject_details(data)
    else:
        return []
    return [
        EntryPoint(path=path, kind=EntryPointKind.PACKAGE_MAIN, detail=_detail(d)) for d in details
    ]


def _package_json_details(data: bytes) -> list[str]:
    try:
        doc = json.loads(data)
    except ValueError:
        return []
    if not isinstance(doc, dict):
        return []
    details = [
        f"{key} -> {doc[key]}" for key in ("main", "module") if isinstance(doc.get(key), str)
    ]
    bin_field = doc.get("bin")
    if isinstance(bin_field, str):
        package = doc.get("name") if isinstance(doc.get("name"), str) else "(unnamed)"
        details.append(f"bin {package} -> {bin_field}")
    elif isinstance(bin_field, dict):
        details.extend(f"bin {k} -> {v}" for k, v in bin_field.items() if isinstance(v, str))
    scripts = doc.get("scripts")
    if isinstance(scripts, dict) and isinstance(scripts.get("start"), str):
        details.append(f"scripts.start: {scripts['start']}")
    return details


def _pyproject_details(data: bytes) -> list[str]:
    try:
        doc = tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        return []
    project = doc.get("project")
    tool = doc.get("tool")
    poetry = tool.get("poetry") if isinstance(tool, dict) else None
    tables = [
        project.get("scripts") if isinstance(project, dict) else None,
        poetry.get("scripts") if isinstance(poetry, dict) else None,
    ]
    details: list[str] = []
    for table in tables:
        if not isinstance(table, dict):
            continue
        for script, target in table.items():
            reference = _script_reference(target)
            if reference:
                details.append(f"script {script} -> {reference}")
    return details


def _script_reference(target: object) -> str | None:
    if isinstance(target, str):
        return target
    if isinstance(target, dict):  # poetry: {callable = "pkg:fn"} / {reference = ...}
        for key in ("callable", "reference"):
            value = target.get(key)
            if isinstance(value, str):
                return value
    return None

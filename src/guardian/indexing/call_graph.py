"""Resolve call sites to internal symbols or third-party package members."""

from collections.abc import Sequence
from typing import NamedTuple

from guardian.core.models import (
    CallRef,
    FileIndex,
    ImportTarget,
    ResolvedCall,
    ResolvedImport,
    SourceLanguage,
    Symbol,
    SymbolKind,
)
from guardian.indexing._resolution_bindings import (
    Binding,
    Context,
    FileBindings,
    build_bindings,
    match_imports,
)
from guardian.indexing._resolution_callee import (
    Segment,
    is_identifier,
    parse_callee,
    split_prefix,
)

_SELF_NAMES = {True: frozenset({"self", "cls"}), False: frozenset({"this"})}
_MAX_PARENT_DEPTH = 64


class _Target(NamedTuple):
    symbol_id: str | None = None
    package: str | None = None
    member: str | None = None
    component_ref: str | None = None


_NO_TARGET = _Target()


def resolve_calls(
    files: Sequence[FileIndex], imports: Sequence[ResolvedImport]
) -> list[ResolvedCall]:
    """One ResolvedCall per CallRef in ``files``, in input order. Pure: no filesystem access."""
    context = Context(files)
    matched = match_imports(files, imports)
    resolved: list[ResolvedCall] = []
    for file_index in files:
        resolver = _FileResolver(context, file_index, build_bindings(file_index, matched))
        for call in file_index.calls:
            target = resolver.resolve(call)
            resolved.append(
                ResolvedCall(
                    path=call.path,
                    line=call.line,
                    callee=call.callee,
                    caller_id=call.caller_id,
                    target_symbol_id=target.symbol_id,
                    package=target.package,
                    member=target.member,
                    component_ref=target.component_ref,
                )
            )
    return resolved


class _FileResolver:
    def __init__(self, context: Context, file_index: FileIndex, bindings: FileBindings) -> None:
        self.context = context
        self.path = file_index.path
        self.is_python = file_index.language is SourceLanguage.PYTHON
        self.bindings = bindings

    def resolve(self, call: CallRef) -> _Target:
        segments = parse_callee(call.callee)
        if not is_identifier(segments[0].name):
            return _NO_TARGET
        names, computed_at = split_prefix(segments)
        exact = computed_at is None
        if names[0] in _SELF_NAMES[self.is_python]:
            return self._self_call(call, names) if exact else _NO_TARGET
        nested = self._nested(call, names) if exact else None
        if nested is not None:
            return _Target(symbol_id=nested.id)
        return self._bound(segments, names, computed_at)

    def _bound(self, segments: list[Segment], names: list[str], computed_at: int | None) -> _Target:
        exact = computed_at is None
        binding = self.bindings.names.get(names[0])
        if binding is None:
            return self._star(names) if exact else _NO_TARGET
        if binding.resolved is not None and binding.resolved.target is not ImportTarget.INTERNAL:
            return _external(binding, names[1:])
        if exact:
            return _symbol_target(self._internal(binding, names[1:]))
        return _symbol_target(self._constructed_method(binding, segments, names, computed_at))

    def _self_call(self, call: CallRef, names: list[str]) -> _Target:
        if len(names) != 2:  # noqa: PLR2004
            return _NO_TARGET
        owner = self._enclosing_class(call.caller_id)
        if owner is None:
            return _NO_TARGET
        return _symbol_target(self.context.lookup(owner.path, f"{owner.qualified_name}.{names[1]}"))

    def _enclosing_class(self, caller_id: str | None) -> Symbol | None:
        current = self.context.by_id.get(caller_id) if caller_id else None
        for _ in range(_MAX_PARENT_DEPTH):
            if current is None:
                return None
            if current.kind is SymbolKind.CLASS:
                return current
            current = self.context.by_id.get(current.parent_id) if current.parent_id else None
        return None

    def _nested(self, call: CallRef, names: list[str]) -> Symbol | None:
        """Functions nested in the caller or its enclosing functions (not class bodies)."""
        current = self.context.by_id.get(call.caller_id) if call.caller_id else None
        dotted = ".".join(names)
        for _ in range(_MAX_PARENT_DEPTH):
            if current is None:
                return None
            if current.kind is not SymbolKind.CLASS:
                found = self.context.lookup(current.path, f"{current.qualified_name}.{dotted}")
                if found is not None:
                    return found
            current = self.context.by_id.get(current.parent_id) if current.parent_id else None
        return None

    def _star(self, names: list[str]) -> _Target:
        for loc in self.bindings.star_locs:
            found = self._in_module(loc, names)
            if found is not None:
                return _Target(symbol_id=found.id)
        return _NO_TARGET

    def _internal(self, binding: Binding, rest: list[str]) -> Symbol | None:
        if binding.symbol is not None:
            if not rest:
                return binding.symbol
            dotted = ".".join(rest)
            return self.context.lookup(
                binding.symbol.path, f"{binding.symbol.qualified_name}.{dotted}"
            )
        if binding.loc is None:
            return None
        return self._in_module(binding.loc, [*binding.member, *rest])

    def _in_module(self, loc: str, segments: list[str]) -> Symbol | None:
        if not self.is_python:
            if segments[:1] == ["default"] and len(segments) > 1:
                segments = segments[1:]
            if not segments or segments == ["default"]:
                return None
            return self.context.lookup(loc, ".".join(segments))
        return self._in_python_module(loc, segments)

    def _in_python_module(self, key: str, segments: list[str]) -> Symbol | None:
        for index in range(len(segments)):
            module_file = self.context.module_file(key)
            if module_file is not None:
                found = self.context.lookup(module_file, ".".join(segments[index:]))
                if found is not None:
                    return found
            key = f"{key}/{segments[index]}" if key else segments[index]
        return None

    def _constructed_method(
        self, binding: Binding, segments: list[Segment], names: list[str], computed_at: int | None
    ) -> Symbol | None:
        """`Cls().method()` / `mod.Cls().method()` -> the method, when Cls is a class."""
        if computed_at is None or computed_at != len(segments) - 2 or segments[-1].computed:
            return None
        owner = self._internal(binding, names[1:])
        if owner is None or owner.kind is not SymbolKind.CLASS:
            return None
        return self.context.lookup(owner.path, f"{owner.qualified_name}.{segments[-1].name}")


def _symbol_target(symbol: Symbol | None) -> _Target:
    return _NO_TARGET if symbol is None else _Target(symbol_id=symbol.id)


def _external(binding: Binding, rest: list[str]) -> _Target:
    resolved = binding.resolved
    if resolved is None or resolved.target is ImportTarget.UNRESOLVED:
        return _NO_TARGET
    member = list(binding.member)
    if member[-1:] == ["default"] and (rest or len(member) > 1):
        member.pop()  # CommonJS interop: `import x from "m"; x.f()` calls module.exports.f
    member.extend(rest)
    return _Target(
        package=resolved.package,
        member=".".join(member) or None,
        component_ref=resolved.component_ref,
    )

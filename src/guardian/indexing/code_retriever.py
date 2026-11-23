"""Focused, bounded, redacted source context for later AI agents.

Source text is untrusted and will be shown to an LLM. It is only ever read through
``read_source`` (no symlinks, must stay inside the root, bounded size), never executed, and
every snippet is passed through ``redact_secrets`` and capped in lines and line length.
"""

import re
from collections import OrderedDict, defaultdict
from collections.abc import Iterable
from pathlib import Path
from typing import NamedTuple

from pydantic import BaseModel, ConfigDict

from guardian.core.models import (
    ChangeDetails,
    CodeIndex,
    Finding,
    FindingKind,
    ResolvedCall,
    ResolvedImport,
    Symbol,
)
from guardian.indexing.repository_indexer import read_source

REDACTED = "[REDACTED]"
MAX_LINE_CHARS = 500
"""Longer lines (minified code, embedded blobs) are cut so one line cannot blow the budget."""
CODE_CONTEXT = 5
USAGE_CONTEXT = 3
IMPORT_CONTEXT = 1
SYMBOL_SNIPPET_MAX = 80
"""CODE findings show the whole enclosing symbol only when it is at most this many lines."""
WINDOW_MAX = 40
CHANGE_TOP_LINES = 30
_FILE_CACHE_SIZE = 32


class CodeSnippet(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str
    start_line: int
    end_line: int
    text: str
    symbol_id: str | None = None
    truncated: bool = False
    redactions: int = 0

    @property
    def line_count(self) -> int:
        return self.end_line - self.start_line + 1


# --- Secret redaction ------------------------------------------------------------------
#
# Every pattern is linear: no nested quantifiers, bounded repetition after variable-length
# prefixes, and lookbehinds so a run of token characters is only scanned from its start.

_PEM_BEGIN = re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----")
_PEM_END = re.compile(r"-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----")
_TOKEN_PATTERNS = (
    re.compile(r"(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}(?![A-Za-z0-9])"),  # AWS access key id
    re.compile(r"(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]{30,}+"),  # GitHub tokens
    re.compile(r"(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{22,}+"),  # GitHub fine-grained
    re.compile(r"(?<![A-Za-z0-9_-])xox[abposr]-[A-Za-z0-9-]{10,}+"),  # Slack tokens
    re.compile(  # JWT: three base64url segments, header starts with '{"'
        r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,}+\.[A-Za-z0-9_-]{5,}+\.[A-Za-z0-9_-]{5,}+"
    ),
)
_ASSIGNMENT = re.compile(
    r"(?i)(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|credential)"
    r"[A-Za-z0-9_.-]{0,40}+"  # rest of the key name, e.g. DB_PASSWORD_PROD, secretKey
    r"""["']?[ \t]{0,10}+(?::|=>|:=|=)[ \t]{0,10}+"""
    r"""(?:"(?P<dq>[^"\r\n]{0,500}+)"|'(?P<sq>[^'\r\n]{0,500}+)')"""
)
_PLACEHOLDER_PREFIXES = ("${", "{{", "%(", "<", "$", "process.env", "os.environ", "env(")
_PLACEHOLDER_VALUES = frozenset(
    {REDACTED.lower(), "changeme", "change-me", "xxx", "xxxx", "***", "none", "null", "todo"}
)


def redact_secrets(text: str) -> tuple[str, int]:
    """Replace likely secrets with ``[REDACTED]``; return the new text and the count.

    A PEM private-key block becomes one ``[REDACTED]`` followed by the newlines it spanned,
    so later line numbers stay valid; an unterminated block is redacted to the end of the
    text. For ``password = "..."``-style assignments only the quoted value is
    replaced, and empty values and placeholders such as ``${DB_PASS}`` are kept.
    """
    text, count = _redact_pem(text)
    for pattern in _TOKEN_PATTERNS:
        text, n = pattern.subn(REDACTED, text)
        count += n
    pieces: list[str] = []
    last = 0
    for match in _ASSIGNMENT.finditer(text):
        group = "dq" if match.group("dq") is not None else "sq"
        value = match.group(group)
        if _is_placeholder(value):
            continue
        start, end = match.span(group)
        pieces.extend((text[last:start], REDACTED))
        last = end
        count += 1
    pieces.append(text[last:])
    return "".join(pieces), count


def _redact_pem(text: str) -> tuple[str, int]:
    pieces: list[str] = []
    count = 0
    pos = 0
    while (begin := _PEM_BEGIN.search(text, pos)) is not None:
        end = _PEM_END.search(text, begin.end())
        stop = end.end() if end is not None else len(text)
        pieces.extend(
            (text[pos : begin.start()], REDACTED, "\n" * text.count("\n", begin.start(), stop))
        )
        count += 1
        pos = stop
    pieces.append(text[pos:])
    return "".join(pieces), count


def _is_placeholder(value: str) -> bool:
    stripped = value.strip()
    return (
        not stripped
        or stripped.startswith(_PLACEHOLDER_PREFIXES)
        or stripped.lower() in _PLACEHOLDER_VALUES
    )


class _Source(NamedTuple):
    lines: list[str]
    pem_blocks: list[tuple[int, int]]
    """1-based inclusive line ranges of private-key blocks; those lines read [REDACTED]."""


def _mask_pem_lines(lines: list[str]) -> list[tuple[int, int]]:
    """Replace every line of a PEM private-key block in place, so a window that starts in
    the middle of a key never shows key material. Linear: each line is examined once."""
    blocks: list[tuple[int, int]] = []
    i = 0
    while i < len(lines):
        if not _PEM_BEGIN.search(lines[i]):
            i += 1
            continue
        j = i
        while j < len(lines) - 1 and not _PEM_END.search(lines[j]):
            j += 1
        lines[i : j + 1] = [REDACTED] * (j + 1 - i)
        blocks.append((i + 1, j + 1))
        i = j + 1
    return blocks


def split_lines(data: bytes) -> list[str]:
    """Decode untrusted bytes (BOM, CRLF and invalid UTF-8 tolerated) into lines that match
    Tree-sitter's 1-based line numbers (only ``\\n`` ends a line)."""
    text = data.decode("utf-8", errors="replace").removeprefix("\ufeff")
    lines = [line.removesuffix("\r") for line in text.split("\n")]
    if lines and lines[-1] == "":
        lines.pop()
    return lines


# --- Retriever -------------------------------------------------------------------------


class CodeRetriever:
    def __init__(
        self, repo_root: Path, index: CodeIndex, *, max_file_bytes: int = 1_048_576
    ) -> None:
        self.repo_root = repo_root
        self.index = index
        self.max_file_bytes = max_file_bytes
        self._symbols_by_path: dict[str, list[Symbol]] = {}
        self._symbols: dict[str, Symbol] = {}
        for file in index.files:
            # Widest first, so the last match in a scan is the innermost.
            ordered = sorted(file.symbols, key=lambda s: (s.span.start_line, -s.span.end_line))
            self._symbols_by_path[file.path] = ordered
            self._symbols.update((s.id, s) for s in ordered)
        self._indexed_paths = frozenset(self._symbols_by_path)
        self._files: OrderedDict[str, _Source | None] = OrderedDict()

    # Lookups

    def symbol(self, symbol_id: str) -> Symbol | None:
        return self._symbols.get(symbol_id)

    def enclosing_symbol(self, path: str, line: int) -> Symbol | None:
        """Innermost symbol whose span contains ``line``."""
        best: Symbol | None = None
        for symbol in self._symbols_by_path.get(path, ()):
            if symbol.span.start_line > line:
                break
            if symbol.span.contains(line) and (best is None or _narrower(symbol, best)):
                best = symbol
        return best

    def usages(self, component_ref: str) -> tuple[list[ResolvedImport], list[ResolvedCall]]:
        imports = [i for i in self.index.imports if i.component_ref == component_ref]
        calls = [c for c in self.index.calls if c.component_ref == component_ref]
        return imports, calls

    # Snippets

    def snippet(
        self, path: str, start_line: int, end_line: int, *, context: int = 3, max_lines: int = 80
    ) -> CodeSnippet | None:
        """Lines ``start-context .. end+context`` clamped to the file and cut to ``max_lines``.

        None when the file cannot be read safely or the range is outside the file."""
        source = self._source(path)
        if not source or max_lines < 1:
            return None
        lines = source.lines
        end_line = max(start_line, end_line)
        first = max(1, start_line - max(0, context))
        last = min(len(lines), end_line + max(0, context))
        if first > last:
            return None
        truncated = last - first + 1 > max_lines
        if truncated:
            last = first + max_lines - 1
        enclosing = self.enclosing_symbol(path, start_line)
        return _build(path, source, (first, last), truncated=truncated, symbol=enclosing)

    def symbol_source(self, symbol_id: str, *, max_lines: int = 120) -> CodeSnippet | None:
        symbol = self._symbols.get(symbol_id)
        if symbol is None or max_lines < 1:
            return None
        source = self._source(symbol.path)
        if not source or not source.lines:
            return None
        first = min(symbol.span.start_line, len(source.lines))
        last = min(symbol.span.end_line, len(source.lines))
        truncated = last - first + 1 > max_lines
        if truncated:
            last = first + max_lines - 1
        return _build(symbol.path, source, (first, last), truncated=truncated, symbol=symbol)

    def for_finding(
        self, finding: Finding, *, max_snippets: int = 5, budget_lines: int = 200
    ) -> list[CodeSnippet]:
        """Source context for one finding, never more than ``max_snippets`` snippets or
        ``budget_lines`` lines in total."""
        budget = _Budget(max_snippets, budget_lines)
        if budget.exhausted:
            return []
        if finding.kind is FindingKind.CODE:
            self._code_context(finding, budget)
        elif finding.kind is FindingKind.VULNERABILITY and finding.component_ref:
            self._usage_context(finding.component_ref, budget)
        elif finding.kind is FindingKind.CHANGE:
            self._change_context(finding, budget)
        return budget.snippets

    # for_finding strategies

    def _code_context(self, finding: Finding, budget: "_Budget") -> None:
        if not finding.path:
            return
        start = finding.start_line or 1
        end = max(start, finding.end_line or start)
        symbol = self._finding_symbol(finding, start)
        if symbol is not None and symbol.span.contains(start):
            size = symbol.span.end_line - symbol.span.start_line + 1
            if size <= min(SYMBOL_SNIPPET_MAX, budget.lines):
                budget.add(self.symbol_source(symbol.id, max_lines=budget.lines))
                return
        budget.add(
            self.snippet(
                finding.path,
                start,
                end,
                context=CODE_CONTEXT,
                max_lines=min(SYMBOL_SNIPPET_MAX, budget.lines),
            )
        )

    def _finding_symbol(self, finding: Finding, start: int) -> Symbol | None:
        symbol = self._symbols.get(finding.symbol_id) if finding.symbol_id else None
        if symbol is not None and symbol.path == finding.path:
            return symbol
        return self.enclosing_symbol(finding.path or "", start)

    def _usage_context(self, component_ref: str, budget: "_Budget") -> None:
        imports, calls = self.usages(component_ref)
        sites = [(c.path, c.line) for c in _distinct_members_first(calls)]
        self._windows(sites, USAGE_CONTEXT, budget)
        self._windows(sorted({(i.path, i.line) for i in imports}), IMPORT_CONTEXT, budget)

    def _windows(self, sites: Iterable[tuple[str, int]], context: int, budget: "_Budget") -> None:
        for path, line in sites:
            if budget.exhausted:
                return
            if budget.covers(path, line):
                continue
            budget.add(
                self.snippet(
                    path, line, line, context=context, max_lines=min(WINDOW_MAX, budget.lines)
                )
            )

    def _change_context(self, finding: Finding, budget: "_Budget") -> None:
        paths = list(finding.details.paths) if isinstance(finding.details, ChangeDetails) else []
        if finding.path:
            paths.insert(0, finding.path)
        for path in dict.fromkeys(paths):
            if budget.exhausted:
                return
            if path in self._indexed_paths:
                budget.add(
                    self.snippet(
                        path,
                        1,
                        CHANGE_TOP_LINES,
                        context=0,
                        max_lines=min(CHANGE_TOP_LINES, budget.lines),
                    )
                )

    # Helpers

    def _source(self, path: str) -> _Source | None:
        if path in self._files:
            self._files.move_to_end(path)
            return self._files[path]
        data = read_source(self.repo_root, path, self.max_file_bytes)
        source = None
        if data is not None:
            lines = split_lines(data)
            source = _Source(lines, _mask_pem_lines(lines))
        self._files[path] = source
        if len(self._files) > _FILE_CACHE_SIZE:
            self._files.popitem(last=False)
        return source


def _build(
    path: str,
    source: _Source,
    span: tuple[int, int],
    *,
    truncated: bool,
    symbol: Symbol | None,
) -> CodeSnippet:
    first, last = span
    window = []
    for line in source.lines[first - 1 : last]:
        if len(line) > MAX_LINE_CHARS:
            line = line[:MAX_LINE_CHARS] + " ..."  # noqa: PLW2901
            truncated = True
        window.append(line)
    text, redactions = redact_secrets("\n".join(window))
    redactions += sum(1 for start, end in source.pem_blocks if start <= last and end >= first)
    return CodeSnippet(
        path=path,
        start_line=first,
        end_line=last,
        text=text,
        symbol_id=symbol.id if symbol else None,
        truncated=truncated,
        redactions=redactions,
    )


class _Budget:
    def __init__(self, max_snippets: int, max_lines: int) -> None:
        self.max_snippets = max_snippets
        self.lines = max(0, max_lines)
        self.snippets: list[CodeSnippet] = []

    @property
    def exhausted(self) -> bool:
        return self.lines <= 0 or len(self.snippets) >= self.max_snippets

    def covers(self, path: str, line: int) -> bool:
        return any(s.path == path and s.start_line <= line <= s.end_line for s in self.snippets)

    def add(self, snippet: CodeSnippet | None) -> None:
        if snippet is None or self.exhausted or snippet.line_count > self.lines:
            return
        self.snippets.append(snippet)
        self.lines -= snippet.line_count


def _narrower(candidate: Symbol, current: Symbol) -> bool:
    size = candidate.span.end_line - candidate.span.start_line
    best = current.span.end_line - current.span.start_line
    return size < best or (size == best and candidate.span.start_line >= current.span.start_line)


def _distinct_members_first(calls: list[ResolvedCall]) -> list[ResolvedCall]:
    """Round-robin over members (sorted by name): the first call to every distinct member
    comes before the second call to any member."""
    by_member: defaultdict[str, list[ResolvedCall]] = defaultdict(list)
    for call in sorted(calls, key=lambda c: (c.path, c.line)):
        by_member[call.member or call.callee].append(call)
    ordered: list[ResolvedCall] = []
    queues = [by_member[m] for m in sorted(by_member)]
    for rank in range(max((len(q) for q in queues), default=0)):
        ordered.extend(q[rank] for q in queues if rank < len(q))
    return ordered

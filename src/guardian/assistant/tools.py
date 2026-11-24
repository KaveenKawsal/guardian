"""Read-only tools the assistant may call over one stored scan.

Every tool reads from the Guardian database (and, for ``code_context``, from the scanned
repository through :class:`CodeRetriever`, which refuses symlinks and paths outside the
root). No tool writes, executes, fetches URLs or reads anything else. Results are compact
JSON-able dicts capped at :data:`MAX_RESULT_BYTES`; everything in them comes from the
scanned repository and is untrusted.
"""

import json
from collections import Counter
from collections.abc import Callable
from functools import cached_property
from pathlib import Path
from typing import Any, cast

from guardian.cli.code import code_summary, package_usage, top_external_packages
from guardian.core.config import GuardianSettings
from guardian.core.exceptions import GuardianError
from guardian.core.models import (
    CodeIndex,
    Finding,
    FindingKind,
    RepositoryProfile,
    Sbom,
    ScanRecord,
    Severity,
    VulnerabilityDetails,
)
from guardian.indexing.code_retriever import CodeRetriever, redact_secrets
from guardian.knowledge.graph_builder import build_knowledge_graph
from guardian.knowledge.graph_queries import DependencyGraph
from guardian.storage.database import Database

MAX_RESULT_BYTES = 8 * 1024
MAX_LIST_LIMIT = 50
DEFAULT_LIMIT = 20
MAX_STRING_CHARS = 1500
MAX_PATHS = 10
MAX_EVIDENCE = 20

Payload = dict[str, Any]

_STRING = {"type": "string"}
_LIMIT = {"type": "integer", "minimum": 1, "maximum": MAX_LIST_LIMIT}


def _spec(name: str, description: str, properties: Payload, required: list[str]) -> Payload:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {"type": "object", "properties": properties, "required": required},
        },
    }


TOOL_SPECS: list[Payload] = [
    _spec(
        "scan_summary",
        "Overview of the current scan: repository, languages, ecosystems, frameworks, finding "
        "counts by severity and kind, dependency and code index totals, tool statuses. "
        "Call this first for broad questions.",
        {},
        [],
    ),
    _spec(
        "list_findings",
        "Security findings of the current scan, most severe first.",
        {
            "min_severity": {
                "type": "string",
                "enum": [s.value for s in Severity],
                "description": "Hide less severe findings (default low).",
            },
            "kind": {
                "type": "string",
                "enum": [k.value for k in FindingKind],
                "description": "Only findings of this kind.",
            },
            "limit": {**_LIMIT, "description": f"Max findings (default {DEFAULT_LIMIT})."},
        },
        [],
    ),
    _spec(
        "get_finding",
        "Full details of one finding: description, package/rule, fix, evidence and how a "
        "vulnerable package enters the dependency tree.",
        {"finding_id": {**_STRING, "description": "Finding id or unique prefix."}},
        ["finding_id"],
    ),
    _spec(
        "code_context",
        "Source code relevant to a finding (flagged lines, or where a vulnerable package is "
        "imported and called). Secrets are redacted.",
        {"finding_id": {**_STRING, "description": "Finding id or unique prefix."}},
        ["finding_id"],
    ),
    _spec(
        "dependency_paths",
        "How a package entered the dependency tree (chains from the repository), its version, "
        "scope and known vulnerabilities.",
        {"package": {**_STRING, "description": "Package name, e.g. lodash or @types/node."}},
        ["package"],
    ),
    _spec(
        "package_usage",
        "Where the indexed source imports a package and which of its members it calls.",
        {"package": {**_STRING, "description": "Package name."}},
        ["package"],
    ),
    _spec(
        "entry_points",
        "Detected entry points (HTTP routes, CLI commands, main modules, ...).",
        {"limit": {**_LIMIT, "description": f"Max entry points (default {DEFAULT_LIMIT})."}},
        [],
    ),
    _spec(
        "search_symbols",
        "Find functions, classes and methods whose name contains the query.",
        {
            "query": {**_STRING, "description": "Case-insensitive name fragment."},
            "limit": {**_LIMIT, "description": f"Max symbols (default {DEFAULT_LIMIT})."},
        },
        ["query"],
    ),
]

TOOL_NAMES = frozenset(spec["function"]["name"] for spec in TOOL_SPECS)


class ToolInputError(GuardianError):
    """The model passed arguments a tool cannot use."""


# --- Size caps ---------------------------------------------------------------------------


def _size(payload: object) -> int:
    return len(json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8"))


def _clip_strings(value: object) -> object:
    if isinstance(value, str):
        return value if len(value) <= MAX_STRING_CHARS else value[:MAX_STRING_CHARS] + "..."
    if isinstance(value, list):
        return [_clip_strings(v) for v in value]
    if isinstance(value, dict):
        return {k: _clip_strings(v) for k, v in value.items()}
    return value


def _largest_list(payload: Payload) -> tuple[Payload, str] | None:
    """The (container, key) of the longest list in the top two levels of ``payload``."""
    best: tuple[Payload, str] | None = None
    best_len = 1
    containers = [payload, *(v for v in payload.values() if isinstance(v, dict))]
    for container in containers:
        for key, value in container.items():
            if isinstance(value, list) and len(value) > best_len:
                best, best_len = (container, key), len(value)
    return best


def fit(payload: Payload, max_bytes: int = MAX_RESULT_BYTES) -> Payload:
    """Shrink ``payload`` below ``max_bytes``: clip long strings, then halve the longest
    lists (recording the original count under ``<key>_total``)."""
    result = cast("Payload", _clip_strings(payload))
    while _size(result) > max_bytes:
        found = _largest_list(result)
        if found is None:
            text = json.dumps(result, ensure_ascii=False, default=str)
            return {"truncated": True, "partial_json": text[: max_bytes // 2]}
        container, key = found
        items = container[key]
        container.setdefault(f"{key}_total", len(items))
        container[key] = items[: len(items) // 2]
        result["truncated"] = True
    return result


def _limit(value: object, default: int = DEFAULT_LIMIT) -> int:
    if value is None:
        return default
    try:
        number = int(value)  # ty: ignore[invalid-argument-type]
    except (TypeError, ValueError):
        msg = f"limit must be an integer, got {value!r}"
        raise ToolInputError(msg) from None
    return max(1, min(number, MAX_LIST_LIMIT))


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        msg = f"{name} must be a non-empty string"
        raise ToolInputError(msg)
    return value.strip()[:200]


def _truncated(items: list[Any], limit: int) -> tuple[list[Any], int]:
    return items[:limit], len(items)


# --- Toolbox -----------------------------------------------------------------------------


class ScanToolbox:
    """The assistant's read-only view of one scan; data is loaded lazily and cached."""

    def __init__(self, db: Database, scan_id: str, settings: GuardianSettings) -> None:
        self.db = db
        self.scan_id = scan_id
        self.settings = settings
        self._handlers: dict[str, Callable[..., Payload]] = {
            "scan_summary": self.scan_summary,
            "list_findings": self.list_findings,
            "get_finding": self.get_finding,
            "code_context": self.code_context,
            "dependency_paths": self.dependency_paths,
            "package_usage": self.package_usage,
            "entry_points": self.entry_points,
            "search_symbols": self.search_symbols,
        }

    # Dispatch

    def call(self, name: str, args: object) -> Payload:
        """Run one tool; errors come back as ``{"error": ...}`` so the model can recover."""
        handler = self._handlers.get(name)
        if handler is None:
            return {"error": f"unknown tool {name!r}; available: {', '.join(sorted(TOOL_NAMES))}"}
        if not isinstance(args, dict):
            args = {}
        allowed = TOOL_SPECS_BY_NAME[name]["function"]["parameters"]["properties"]
        kwargs = {k: v for k, v in args.items() if k in allowed}
        try:
            return fit(handler(**kwargs))
        except (GuardianError, TypeError) as exc:
            return {"error": str(exc)[:300]}

    def serialize(self, payload: Payload) -> str:
        """JSON text for the model, with secrets redacted as a last line of defence."""
        text, _ = redact_secrets(json.dumps(payload, ensure_ascii=False, default=str))
        return text

    # Lazy data

    @cached_property
    def record(self) -> ScanRecord:
        return self.db.scans.get(self.scan_id)

    @cached_property
    def profile(self) -> RepositoryProfile:
        return self.db.scans.profile(self.scan_id)

    @cached_property
    def sbom(self) -> Sbom | None:
        return self.db.sboms.load(self.scan_id)

    @cached_property
    def findings(self) -> list[Finding]:
        return self.db.findings.load(self.scan_id)

    @cached_property
    def code_index(self) -> CodeIndex | None:
        return self.db.code.load(self.scan_id)

    @cached_property
    def graph(self) -> DependencyGraph:
        changes = self.db.findings.changes(self.scan_id)
        return DependencyGraph(
            build_knowledge_graph(self.profile, self.sbom, self.findings, changes)
        )

    def _finding(self, finding_id: object) -> Finding:
        return self.db.findings.get(self.scan_id, _text(finding_id, "finding_id"))

    # Tools

    def scan_summary(self) -> Payload:
        record, profile = self.record, self.profile
        findings = self.findings
        payload: Payload = {
            "scan_id": record.id,
            "repository": record.repository_name,
            "status": record.status.value,
            "started_at": record.started_at.isoformat(),
            "git_branch": record.git_branch,
            "git_commit": record.git_commit,
            "languages": [lang.name for lang in profile.languages[:10]],
            "ecosystems": [
                {
                    "ecosystem": eco.ecosystem.value,
                    "package_managers": eco.package_managers,
                    "frameworks": [f.name for f in eco.frameworks],
                }
                for eco in profile.ecosystems
            ],
            "findings_total": len(findings),
            "findings_by_severity": dict(Counter(f.severity.value for f in findings)),
            "findings_by_kind": dict(Counter(f.kind.value for f in findings)),
            "components": len(self.sbom.components) if self.sbom else None,
            "tool_runs": {run.tool: run.status for run in record.tool_runs},
            "warnings": record.warnings[:10],
        }
        index = self.code_index
        if index is None:
            payload["code_index"] = None
        else:
            summary = code_summary(index)
            payload["code_index"] = {
                "files": summary["files"],
                "symbols": summary["symbols"],
                "entry_points": summary["entry_points"],
                "top_external_packages": top_external_packages(index),
            }
        return payload

    def list_findings(
        self, min_severity: object = None, kind: object = None, limit: object = None
    ) -> Payload:
        try:
            severity = Severity(min_severity) if min_severity else Severity.LOW
            wanted_kind = FindingKind(kind) if kind else None
        except ValueError as exc:
            raise ToolInputError(str(exc)) from None
        rows = [
            f
            for f in self.findings
            if f.severity.rank >= severity.rank and (wanted_kind is None or f.kind is wanted_kind)
        ]
        shown, total = _truncated(rows, _limit(limit))
        return {
            "total": total,
            "shown": len(shown),
            "findings": [_finding_row(f) for f in shown],
        }

    def get_finding(self, finding_id: object) -> Payload:
        finding = self._finding(finding_id)
        details = finding.details.model_dump(mode="json", exclude_none=True)
        payload: Payload = {
            "id": finding.id,
            "title": finding.title,
            "severity": finding.severity.value,
            "kind": finding.kind.value,
            "tool": finding.tool,
            "location": finding.location,
            "symbol_id": finding.symbol_id,
            "introduced_by": finding.introduced_by,
            "details": details,
            "evidence": [
                e.model_dump(mode="json", exclude_none=True)
                for e in finding.evidence[:MAX_EVIDENCE]
            ],
        }
        if finding.component_ref:
            paths = self.graph.introduction_paths(finding.component_ref)
            payload["introduction_paths"] = [
                [c.display_name for c in path] for path in paths[:MAX_PATHS]
            ]
        payload["reported_in_scans"] = len(self.db.findings.scans_containing(finding.id))
        return payload

    def code_context(self, finding_id: object) -> Payload:
        finding = self._finding(finding_id)
        index = self.code_index
        if index is None:
            return {"finding_id": finding.id, "error": "this scan has no code index"}
        root = Path(self.record.repository_root)
        if not root.is_dir():
            return {"finding_id": finding.id, "error": "the scanned source is no longer on disk"}
        retriever = CodeRetriever(root, index, max_file_bytes=self.settings.max_source_bytes)
        snippets = retriever.for_finding(finding, max_snippets=4, budget_lines=120)
        return {
            "finding_id": finding.id,
            "snippets": [
                {
                    "path": s.path,
                    "start_line": s.start_line,
                    "end_line": s.end_line,
                    "symbol_id": s.symbol_id,
                    "truncated": s.truncated,
                    "text": s.text,
                }
                for s in snippets
            ],
            "note": None if snippets else "no source context found for this finding",
        }

    def dependency_paths(self, package: object) -> Payload:
        name = _text(package, "package")
        if self.sbom is None:
            return {"package": name, "error": "this scan has no SBOM"}
        graph = self.graph
        matches = graph.find(name)
        if not matches:
            return {"package": name, "found": False}
        results = []
        for component in matches[:5]:
            paths = graph.introduction_paths(component.ref)
            results.append(
                {
                    "component": component.display_name,
                    "scope": component.scope.value,
                    "direct": bool(paths) and len(paths[0]) == 1,
                    "paths": [[c.display_name for c in p] for p in paths[:MAX_PATHS]],
                    "vulnerabilities": [
                        {"id": f.id, "severity": f.severity.value, "title": f.title}
                        for f in graph.findings_for_component(component.ref)[:MAX_PATHS]
                    ],
                }
            )
        return {"package": name, "found": True, "matches": results}

    def package_usage(self, package: object) -> Payload:
        name = _text(package, "package")
        index = self.code_index
        if index is None:
            return {"package": name, "error": "this scan has no code index"}
        imports, calls = package_usage(index, name)
        shown_imports, import_total = _truncated(imports, MAX_LIST_LIMIT)
        shown_calls, call_total = _truncated(calls, MAX_LIST_LIMIT)
        return {
            "package": name,
            "importing_files": sorted({i.path for i in imports})[:MAX_LIST_LIMIT],
            "imports_total": import_total,
            "imports": [f"{i.path}:{i.line} {i.module}" for i in shown_imports],
            "calls_total": call_total,
            "members": dict(Counter(c.member or c.callee for c in calls).most_common(30)),
            "calls": [
                {"at": f"{c.path}:{c.line}", "callee": c.callee, "in": c.caller_id}
                for c in shown_calls
            ],
        }

    def entry_points(self, limit: object = None) -> Payload:
        index = self.code_index
        if index is None:
            return {"error": "this scan has no code index"}
        entries = sorted(index.entry_points, key=lambda e: (e.kind.value, e.path, e.line or 0))
        shown, total = _truncated(entries, _limit(limit))
        return {
            "total": total,
            "entry_points": [
                {
                    "kind": e.kind.value,
                    "at": f"{e.path}:{e.line}" if e.line else e.path,
                    "detail": e.detail,
                    "symbol_id": e.symbol_id,
                }
                for e in shown
            ],
        }

    def search_symbols(self, query: object, limit: object = None) -> Payload:
        wanted = _text(query, "query").lower()
        index = self.code_index
        if index is None:
            return {"query": wanted, "error": "this scan has no code index"}
        matches = [
            s
            for f in index.files
            for s in f.symbols
            if wanted in s.name.lower() or wanted in s.qualified_name.lower()
        ]
        matches.sort(key=lambda s: (s.name.lower() != wanted, s.path, s.span.start_line))
        shown, total = _truncated(matches, _limit(limit))
        return {
            "query": wanted,
            "total": total,
            "symbols": [
                {
                    "id": s.id,
                    "name": s.qualified_name,
                    "kind": s.kind.value,
                    "at": f"{s.path}:{s.span.start_line}-{s.span.end_line}",
                }
                for s in shown
            ],
        }


TOOL_SPECS_BY_NAME = {spec["function"]["name"]: spec for spec in TOOL_SPECS}


def _finding_row(f: Finding) -> Payload:
    package = f.details.package if isinstance(f.details, VulnerabilityDetails) else None
    return {
        "id": f.id,
        "severity": f.severity.value,
        "kind": f.kind.value,
        "title": f.title,
        "where": f.location or package,
    }

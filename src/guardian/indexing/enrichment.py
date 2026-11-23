"""Enrich security findings with codebase context from the CodeIndex.

Pure functions over models: no filesystem, database or network access. Each pass indexes
the CodeIndex once (by path or component ref), so cost stays linear in index + findings.
"""

from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field

from guardian.core.models import (
    CodeIndex,
    Evidence,
    EvidenceKind,
    Finding,
    FindingKind,
    ResolvedCall,
    ResolvedImport,
    SourceLanguage,
    Symbol,
    VulnerabilityDetails,
)

INDEXER = "indexer"
MAX_LOCATIONS = 5
MAX_MEMBERS = 5
NOT_IMPORTED = (
    "Not imported directly by the indexed source (enters as a dependency of other packages, "
    "or is used by tooling)"
)

PYTHON_FAMILY = "python"
JS_FAMILY = "javascript"

_LANGUAGE_FAMILY = {
    SourceLanguage.PYTHON: PYTHON_FAMILY,
    SourceLanguage.JAVASCRIPT: JS_FAMILY,
    SourceLanguage.TYPESCRIPT: JS_FAMILY,
    SourceLanguage.TSX: JS_FAMILY,
}
# OSV ecosystem names, purl types and Guardian Ecosystem values -> language family.
_ECOSYSTEM_FAMILY = {
    "pypi": PYTHON_FAMILY,
    "python": PYTHON_FAMILY,
    "npm": JS_FAMILY,
    "node": JS_FAMILY,
}


def attach_symbols(findings: Iterable[Finding], index: CodeIndex) -> list[Finding]:
    """Set ``symbol_id`` of CODE findings to the innermost symbol enclosing their line."""
    symbols_by_path = {f.path: f.symbols for f in index.files if f.symbols}
    enriched: list[Finding] = []
    for finding in findings:
        symbol = _symbol_for(finding, symbols_by_path)
        enriched.append(finding.model_copy(update={"symbol_id": symbol.id}) if symbol else finding)
    return enriched


def _symbol_for(finding: Finding, symbols_by_path: dict[str, list[Symbol]]) -> Symbol | None:
    if finding.kind is not FindingKind.CODE or not finding.path or not finding.start_line:
        return None
    line = finding.start_line
    enclosing = [s for s in symbols_by_path.get(finding.path, ()) if s.span.contains(line)]
    if not enclosing:
        return None
    # Innermost: the shortest span; on a tie the one starting later (nested on one line).
    return min(enclosing, key=lambda s: (s.span.end_line - s.span.start_line, -s.span.start_line))


@dataclass
class _Usage:
    imports: list[ResolvedImport] = field(default_factory=list)
    members: Counter[str] = field(default_factory=Counter)


def add_usage_evidence(findings: Iterable[Finding], index: CodeIndex) -> list[Finding]:
    """Append one CODE_USAGE evidence item to each VULNERABILITY finding with a component,
    saying where the repository imports and calls it, or that it does not import it."""
    families = {_LANGUAGE_FAMILY[f.language] for f in index.files}
    usage = _usage_by_component(index)
    enriched: list[Finding] = []
    for finding in findings:
        if (
            finding.kind is not FindingKind.VULNERABILITY
            or finding.component_ref is None
            or _finding_family(finding) not in families
        ):
            enriched.append(finding)
            continue
        evidence = _usage_evidence(usage.get(finding.component_ref))
        enriched.append(finding.model_copy(update={"evidence": [*finding.evidence, evidence]}))
    return enriched


def _usage_by_component(index: CodeIndex) -> dict[str, _Usage]:
    usage: dict[str, _Usage] = defaultdict(_Usage)
    for imp in index.imports:
        if imp.component_ref:
            usage[imp.component_ref].imports.append(imp)
    for call in index.calls:
        if call.component_ref and call.component_ref in usage:
            usage[call.component_ref].members[_member(call)] += 1
    return dict(usage)


def _member(call: ResolvedCall) -> str:
    return call.member or call.callee


def _usage_evidence(usage: _Usage | None) -> Evidence:
    if usage is None or not usage.imports:
        return Evidence(kind=EvidenceKind.CODE_USAGE, tool=INDEXER, summary=NOT_IMPORTED)
    first_per_file: dict[str, ResolvedImport] = {}
    for imp in sorted(usage.imports, key=lambda i: (i.path, i.line)):
        first_per_file.setdefault(imp.path, imp)
    locations = [f"{i.path}:{i.line}" for i in first_per_file.values()]
    shown = ", ".join(locations[:MAX_LOCATIONS])
    more = len(locations) - MAX_LOCATIONS
    summary = f"Imported in {len(locations)} file(s): {shown}" + (
        f" and {more} more" if more > 0 else ""
    )
    if usage.members:
        ranked = sorted(usage.members.items(), key=lambda kv: (-kv[1], kv[0]))
        summary += "; calls: " + ", ".join(f"{m} ({n})" for m, n in ranked[:MAX_MEMBERS])
    first = next(iter(first_per_file.values()))
    return Evidence(
        kind=EvidenceKind.CODE_USAGE,
        tool=INDEXER,
        summary=summary,
        path=first.path,
        line=first.line,
    )


def _finding_family(finding: Finding) -> str | None:
    details = finding.details
    if isinstance(details, VulnerabilityDetails) and details.ecosystem:
        family = _ECOSYSTEM_FAMILY.get(details.ecosystem.lower())
        if family:
            return family
    for ref in (
        details.purl if isinstance(details, VulnerabilityDetails) else None,
        finding.component_ref,
    ):
        if ref and ref.lower().startswith("pkg:"):
            purl_type = ref[4:].split("/", 1)[0].lower()
            if family := _ECOSYSTEM_FAMILY.get(purl_type):
                return family
    return None

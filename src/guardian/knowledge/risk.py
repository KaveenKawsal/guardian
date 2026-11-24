"""Deterministic risk assessment (Guardian heuristic).

R = 0.35 S + 0.25 E + 0.20 X + 0.10 P + 0.10 F, each factor in [0, 1] or unknown (None).
The score is the weighted mean of the *known* factors x 100, so missing evidence lowers the
confidence instead of the score. Pure: no I/O, no network, no LLM.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field

from guardian.core.models import (
    RISK_WEIGHTS,
    ChangeCategory,
    ChangeDetails,
    CodeDetails,
    CodeIndex,
    Component,
    Confidence,
    DependencyScope,
    Finding,
    Priority,
    RiskAssessment,
    RiskFactor,
    RiskFactorName,
    Severity,
    SourceLanguage,
    VulnerabilityDetails,
)
from guardian.indexing.entry_points import is_test_path
from guardian.knowledge.graph_queries import DependencyGraph

S = RiskFactorName.SEVERITY
E = RiskFactorName.EXPOSURE
X = RiskFactorName.EXPLOITABILITY
P = RiskFactorName.REACHABILITY
F = RiskFactorName.FIX

SEVERITY_VALUES: dict[Severity, float | None] = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.8,
    Severity.MEDIUM: 0.5,
    Severity.LOW: 0.25,
    Severity.INFO: 0.05,
    Severity.UNKNOWN: None,
}
LIKELIHOOD_VALUES = {"HIGH": 0.8, "MEDIUM": 0.5, "LOW": 0.2}
CHANGE_EXPOSURE = {
    ChangeCategory.CI_CONFIG: 0.6,
    ChangeCategory.LOCKFILE_ONLY: 0.5,
}
OPTIONAL_SCOPES = frozenset({DependencyScope.OPTIONAL, DependencyScope.EXCLUDED})
HIGH_CONFIDENCE = 0.75
MEDIUM_CONFIDENCE = 0.5
P1_SCORE, P2_SCORE, P3_SCORE = 70, 50, 30
P1_SEVERITIES = frozenset({Severity.CRITICAL, Severity.HIGH})
CALLED_REACHABILITY = 0.7
DIRECT, SECOND_LEVEL = 1, 2
NOT_ASSESSED = "Not assessed: requires AI investigation"

_LANGUAGE_FAMILIES: dict[SourceLanguage, str] = {
    SourceLanguage.PYTHON: "pypi",
    SourceLanguage.JAVASCRIPT: "npm",
    SourceLanguage.TYPESCRIPT: "npm",
    SourceLanguage.TSX: "npm",
}
_ECOSYSTEM_FAMILIES = {"pypi": "pypi", "python": "pypi", "npm": "npm", "node": "npm"}

SEVERITY_WORDS = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High-severity",
    Severity.MEDIUM: "Medium-severity",
    Severity.LOW: "Low-severity",
    Severity.INFO: "Informational",
    Severity.UNKNOWN: "Unrated",
}


@dataclass
class _Usage:
    """Where the indexed code touches one component (first site kept for rationales)."""

    imported_in: str | None = None
    called_in: str | None = None
    members: set[str] = field(default_factory=set)


@dataclass
class _Context:
    """Facts precomputed once per assessment run."""

    components: dict[str, Component]
    depths: dict[str, int]
    usage: dict[str, _Usage]
    indexed_files: frozenset[str]
    covered_families: frozenset[str]
    entry_point_files: frozenset[str]
    called_symbols: frozenset[str]
    has_index: bool

    @classmethod
    def build(cls, graph: DependencyGraph, code_index: CodeIndex | None) -> "_Context":
        g = graph.graph
        components = {
            d["component"].ref: d["component"] for _, d in g.nodes(data=True) if "component" in d
        }
        if code_index is None:
            code_index = CodeIndex()
            has_index = False
        else:
            has_index = True
        usage = _usage(code_index, frozenset(components))
        return cls(
            components=components,
            depths=graph.depths(),
            usage=usage,
            indexed_files=frozenset(f.path for f in code_index.files),
            covered_families=language_families(code_index),
            entry_point_files=frozenset(e.path for e in code_index.entry_points),
            called_symbols=frozenset(
                c.target_symbol_id
                for c in code_index.calls
                if c.target_symbol_id and c.target_symbol_id != c.caller_id
            ),
            has_index=has_index,
        )

    def covers(self, component: Component | None, details: VulnerabilityDetails) -> bool:
        """True when the code index includes the language family of the component."""
        return package_family(component, details.ecosystem) in self.covered_families


def _usage(index: CodeIndex, refs: frozenset[str]) -> dict[str, _Usage]:
    """Per component: first importing / calling file (non-test files first) and members.

    Read from the index rather than the graph: the graph keeps one edge per node pair, so a
    module-level call from a file that also imports the package is folded into the import."""
    usage: dict[str, _Usage] = {}

    def better(current: str | None, path: str) -> str:
        if current is None:
            return path
        return min(current, path, key=lambda p: (is_test_path(p), p))

    for imp in index.imports:
        if imp.component_ref in refs:
            item = usage.setdefault(imp.component_ref, _Usage())
            item.imported_in = better(item.imported_in, imp.path)
    for call in index.calls:
        if call.component_ref in refs:
            item = usage.setdefault(call.component_ref, _Usage())
            item.called_in = better(item.called_in, call.path)
            if call.member:
                item.members.add(call.member)
    return usage


def language_families(code_index: CodeIndex | None) -> frozenset[str]:
    """Package families ("npm", "pypi") whose source language the code index covers."""
    if code_index is None:
        return frozenset()
    return frozenset(
        _LANGUAGE_FAMILIES[f.language] for f in code_index.files if f.language in _LANGUAGE_FAMILIES
    )


def package_family(component: Component | None, ecosystem: str | None) -> str | None:
    """ "npm" / "pypi" for a component (purl type first, then the advisory ecosystem)."""
    family = (component.purl_type if component else None) or ecosystem or ""
    return _ECOSYSTEM_FAMILIES.get(family.lower())


def assess(
    findings: Sequence[Finding],
    graph: DependencyGraph,
    code_index: CodeIndex | None,
) -> list[RiskAssessment]:
    """One RiskAssessment per finding, same order. Pure: no I/O, no LLM."""
    context = _Context.build(graph, code_index)
    return [_assess_one(finding, context) for finding in findings]


def _assess_one(finding: Finding, ctx: _Context) -> RiskAssessment:
    details = finding.details
    if isinstance(details, VulnerabilityDetails):
        factors, summary = _vulnerability(finding, details, ctx)
    elif isinstance(details, CodeDetails):
        factors, summary = _code(finding, details, ctx)
    else:
        factors, summary = _change(finding, details)
    known = [f for f in factors if f.value is not None]
    known_weight = round(sum(f.weight for f in known), 4)
    score = (
        round(100 * sum(f.weight * f.value for f in known if f.value is not None) / known_weight, 1)
        if known_weight
        else None
    )
    reachability = next(f.value for f in factors if f.name is P)
    return RiskAssessment(
        finding_id=finding.id,
        score=score,
        known_weight=known_weight,
        confidence=_confidence(known_weight),
        priority=_priority(score, finding.severity, reachability, known_weight),
        factors=factors,
        summary=summary,
    )


def _confidence(known_weight: float) -> Confidence:
    if known_weight >= HIGH_CONFIDENCE:
        return Confidence.HIGH
    if known_weight >= MEDIUM_CONFIDENCE:
        return Confidence.MEDIUM
    return Confidence.LOW


def _priority(
    score: float | None,
    severity: Severity,
    reachability: float | None,
    known_weight: float = 1.0,
) -> Priority:
    if severity is Severity.INFO:
        return Priority.P4
    if (
        severity is Severity.CRITICAL
        and reachability is not None
        and reachability >= CALLED_REACHABILITY
    ):
        return Priority.P1
    if score is None:
        return Priority.P3
    thresholds = ((P1_SCORE, Priority.P1), (P2_SCORE, Priority.P2), (P3_SCORE, Priority.P3))
    priority = next((p for limit, p in thresholds if score >= limit), Priority.P4)
    # A high score resting on less than half of the evidence weight is not "act now".
    if priority is Priority.P1 and known_weight < MEDIUM_CONFIDENCE:
        return Priority.P2
    # Exposure and reachability amplify severity; they cannot turn a medium issue into P1.
    if priority is Priority.P1 and severity not in P1_SEVERITIES:
        return Priority.P2
    return priority


def _factor(name: RiskFactorName, value: float | None, rationale: str) -> RiskFactor:
    return RiskFactor(name=name, weight=RISK_WEIGHTS[name], value=value, rationale=rationale)


def _severity_factor(finding: Finding, cvss: float | None = None) -> RiskFactor:
    if cvss is not None:
        value = min(max(cvss / 10, 0.0), 1.0)
        return _factor(S, value, f"CVSS score {cvss:g} ({finding.severity.value})")
    value = SEVERITY_VALUES[finding.severity]
    if value is None:
        return _factor(S, None, "Severity unknown")
    return _factor(S, value, f"Rated {finding.severity.value} by {finding.tool}")


# --- Vulnerabilities -------------------------------------------------------------------


def _vulnerability(
    finding: Finding, d: VulnerabilityDetails, ctx: _Context
) -> tuple[list[RiskFactor], str]:
    ref = finding.component_ref
    component = ctx.components.get(ref) if ref else None
    name = component.name if component else d.package
    depth = ctx.depths.get(ref) if ref else None

    exposure, where = _vulnerability_exposure(name, component, depth)
    reach, how = _vulnerability_reachability(name, component, d, ctx)
    if d.recommended_fix:
        fix = _factor(F, 1.0, f"Upgrade to {d.recommended_fix} fixes it")
        remedy = f"upgrade to {d.recommended_fix} available"
    elif d.fixed_versions:
        fix = _factor(F, 0.6, f"Fixed in {', '.join(d.fixed_versions[:3])} (other branch)")
        remedy = "fixed releases exist"
    else:
        fix = _factor(F, 0.2, "No fixed version published")
        remedy = "no fix published"
    factors = [
        _severity_factor(finding, d.cvss_score),
        exposure,
        _factor(X, None, NOT_ASSESSED),
        reach,
        fix,
    ]
    severity = SEVERITY_WORDS[finding.severity]
    summary = f"{severity} vulnerability in {where} {name}{how}; {remedy}."
    return factors, summary


def _vulnerability_exposure(
    name: str, component: Component | None, depth: int | None
) -> tuple[RiskFactor, str]:
    if depth is None:
        return _factor(E, None, f"{name} is not linked to the dependency tree"), "dependency"
    if depth == DIRECT:
        value, where = 0.8, "direct dependency"
    elif depth == SECOND_LEVEL:
        value, where = 0.6, "transitive dependency"
    else:
        value, where = 0.4, "deep transitive dependency"
    text = f"{name} is a {where}" + ("" if depth == DIRECT else f" (depth {depth})")
    if component is not None and component.scope in OPTIONAL_SCOPES:
        value *= 0.5
        text += f", {component.scope.value} scope (dev/optional)"
        where = f"{component.scope.value} {where}"
    return _factor(E, value, text), where


def _vulnerability_reachability(
    name: str, component: Component | None, d: VulnerabilityDetails, ctx: _Context
) -> tuple[RiskFactor, str]:
    if component is None or not ctx.covers(component, d):
        return _factor(P, None, "Code index does not cover this package's language"), ""
    usage = ctx.usage.get(component.ref)
    if usage and usage.called_in:
        members = sorted(usage.members)
        called = f"{name}.{members[0]}" if members else name
        return (
            _factor(P, 1.0, f"{called} called in {usage.called_in}"),
            " that the code calls",
        )
    if usage and usage.imported_in:
        return (
            _factor(P, 0.7, f"{name} imported in {usage.imported_in}, no resolved calls"),
            " that the code imports",
        )
    return _factor(
        P, 0.2, f"{name} is not imported by indexed source"
    ), " that the code never imports"


# --- Code findings ---------------------------------------------------------------------


def _code(finding: Finding, d: CodeDetails, ctx: _Context) -> tuple[list[RiskFactor], str]:
    path = finding.path or ""
    in_test = bool(path) and is_test_path(path)
    has_entry = path in ctx.entry_point_files

    if in_test:
        exposure, where = _factor(E, 0.1, f"{path} is test code"), "test code"
    elif has_entry:
        exposure = _factor(E, 1.0, f"{path} contains an entry point or route")
        where = "a file with an entry point"
    else:
        exposure, where = _factor(E, 0.6, f"{path or 'location'} is application code"), path

    likelihood = (d.likelihood or "").upper()
    if likelihood in LIKELIHOOD_VALUES:
        exploit = _factor(X, LIKELIHOOD_VALUES[likelihood], f"Semgrep likelihood {likelihood}")
    else:
        exploit = _factor(X, None, f"{NOT_ASSESSED} (rule declares no likelihood)")

    factors = [
        _severity_factor(finding),
        exposure,
        exploit,
        _code_reachability(finding, ctx, in_test=in_test, has_entry=has_entry),
        _factor(F, 0.8, "Fix is local to the repository's own code"),
    ]
    rule = d.rule_id.rsplit(".", 1)[-1]
    severity = SEVERITY_WORDS[finding.severity]
    summary = f"{severity} code finding ({rule}) in {where or 'the repository'}"
    if likelihood in LIKELIHOOD_VALUES:
        summary += f"; Semgrep rates exploit likelihood {likelihood.lower()}"
    return factors, summary + "."


def _code_reachability(
    finding: Finding, ctx: _Context, *, in_test: bool, has_entry: bool
) -> RiskFactor:
    path = finding.path or ""
    if not ctx.has_index:
        return _factor(P, None, "No code index")
    if in_test:
        return _factor(P, 0.1, "Only reachable from tests")
    if path not in ctx.indexed_files:
        return _factor(P, None, f"{path or 'File'} is not in the code index")
    if finding.symbol_id and finding.symbol_id in ctx.called_symbols:
        return _factor(P, 0.9, f"{finding.symbol_id} is called by other code")
    if has_entry:
        return _factor(P, 0.9, f"{path} defines an entry point")
    subject = f"of {finding.symbol_id}" if finding.symbol_id else "into the flagged code"
    return _factor(P, 0.5, f"No indexed callers {subject}")


# --- Change findings -------------------------------------------------------------------


def _change(finding: Finding, d: ChangeDetails) -> tuple[list[RiskFactor], str]:
    files = ", ".join(d.paths[:3]) or "repository"
    if d.category is ChangeCategory.SENSITIVE_FILE:
        present = "still present" in finding.title.lower()
        value = 1.0 if present else 0.7
        state = "still present" if present else "removed but kept in git history"
        exposure = _factor(E, value, f"Sensitive file {files} {state}")
    else:
        value = CHANGE_EXPOSURE.get(d.category, 0.2)
        exposure = _factor(E, value, f"{d.category.value} touching {files}")
    factors = [
        _severity_factor(finding),
        exposure,
        _factor(X, None, NOT_ASSESSED),
        _factor(P, None, "Not applicable to repository changes"),
        _factor(F, 0.8, "Actionable by the repository owner"),
    ]
    commit = f" in commit {d.commit[:12]}" if d.commit else " (uncommitted)"
    severity = SEVERITY_WORDS[finding.severity]
    summary = f"{severity} repository change ({d.category.value}){commit} affecting {files}."
    return factors, summary

"""Deterministic remediation candidates for vulnerable npm packages.

Every candidate is a fact-based option with an ID; the planner (deterministic or LLM) may only
choose among them. Versions come from the npm registry (``version_verified=True``) or, when the
registry is unreachable, from the OSV fixed versions (``version_verified=False``). Whether a
version is affected is decided by the OSV ranges (``analysis.osv.is_affected``), never by an LLM.

Candidate order: direct upgrades, partial upgrades, parent upgrades, overrides, REMOVE, then the
non-code BLOCK and ESCALATE, which are always present.
"""

import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol

from packageurl import PackageURL

from guardian.analysis.osv import is_affected
from guardian.core.models import (
    CodeIndex,
    Component,
    Finding,
    RiskAssessment,
    Sbom,
    VulnerabilityDetails,
)
from guardian.core.remediation_models import (
    RemediationActionType,
    RemediationCandidate,
    RemediationCase,
    SemverJump,
    candidate_id_for,
)
from guardian.knowledge.graph_builder import component_node
from guardian.knowledge.graph_queries import DependencyGraph
from guardian.knowledge.risk import assess
from guardian.remediation import npm_semver
from guardian.remediation.registry import PackageVersions

ROOT_MANIFEST = "package.json"
MAX_MANIFEST_BYTES = 5 * 1024 * 1024
DEFAULT_WORKTREE_ROOT = "~/.guardian/worktrees"
INSTALLED_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")
MAX_PARTIAL_CANDIDATES = 2

Strategy = Literal["direct", "parent", "override"]


class RegistryLike(Protocol):
    def fetch(self, name: str) -> PackageVersions | None: ...


# --- Helpers shared with the adapter and the case builder --------------------------------


def npm_purl(name: str, version: str | None = None) -> str:
    """``pkg:npm/<name>[@version]``; scoped names become ``pkg:npm/%40scope/name``."""
    namespace, _, short = name.rpartition("/")
    return PackageURL(
        type="npm", namespace=namespace or None, name=short, version=version
    ).to_string()


def read_manifest(repo_root: Path, relative: str = ROOT_MANIFEST) -> dict[str, Any] | None:
    """Parse a package.json inside ``repo_root``; None when missing, unsafe or invalid."""
    root = repo_root.resolve()
    path = root / relative
    try:
        if path.is_symlink() or not path.is_file():
            return None
        if not path.resolve().is_relative_to(root):
            return None
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def find_dependency(manifest: Mapping[str, Any], name: str) -> tuple[str, str] | None:
    """(section, spec) of ``name`` in the installed dependency sections."""
    for section in INSTALLED_SECTIONS:
        deps = manifest.get(section)
        if isinstance(deps, dict) and isinstance(deps.get(name), str):
            return section, deps[name]
    return None


def semver_jump(from_version: str | None, to_version: str | None) -> SemverJump:
    if not from_version or not to_version:
        return SemverJump.UNKNOWN
    kind = npm_semver.jump(from_version, to_version)
    return SemverJump(kind) if kind else SemverJump.UNKNOWN


def is_npm_finding(finding: Finding) -> bool:
    d = finding.details
    if not isinstance(d, VulnerabilityDetails):
        return False
    return (d.ecosystem or "").lower() == "npm" or (d.purl or "").startswith("pkg:npm/")


# --- Generation context ------------------------------------------------------------------


@dataclass
class _Context:
    case: RemediationCase
    name: str
    current: str | None
    purl: str
    findings: list[Finding]
    graph: DependencyGraph
    code_index: CodeIndex | None
    assessments: dict[str, RiskAssessment]
    registry: RegistryLike | None
    repo_root: Path
    worktree_root: str
    component: Component | None = None
    manifest: dict[str, Any] | None = None
    manifest_path: str | None = None
    section: str | None = None
    spec: str | None = None
    package: PackageVersions | None = None
    package_loaded: bool = False
    fetched: dict[str, PackageVersions | None] = field(default_factory=dict)
    advisory_notes: dict[str, list[str]] = field(default_factory=dict)
    """Per target version: what the target-version advisory check found (for the notes)."""
    advisory_lookups: int = 0

    def fetch(self, name: str) -> PackageVersions | None:
        if name not in self.fetched:
            self.fetched[name] = self.registry.fetch(name) if self.registry else None
        return self.fetched[name]

    @property
    def details(self) -> list[VulnerabilityDetails]:
        return [f.details for f in self.findings if isinstance(f.details, VulnerabilityDetails)]

    def still_affected(self, version: str) -> list[Finding]:
        return [
            f
            for f in self.findings
            if isinstance(f.details, VulnerabilityDetails) and is_affected(version, f.details)
        ]

    def rollback(self, restore: str | None) -> str:
        base = (
            f"git worktree remove {self.worktree_root}/{self.case.id} "
            f"&& git branch -D guardian/fix-{self.case.id}"
        )
        return f"{base}; or {restore}" if restore else base

    def evidence(self, extra: Sequence[str] = ()) -> list[str]:
        items = [f"finding:{f.id}" for f in self.findings]
        for d in self.details:
            items.append(f"advisory:{d.vulnerability_id}")
            items += [f"advisory:{a}" for a in d.aliases]
        return [*dict.fromkeys(items), *extra]


MAX_ADVISORY_LOOKUPS = 8
"""Target-version advisory lookups per case (each is one OSV query, cached for 24 h)."""


def _target_advisories(ctx: _Context, name: str, version: str) -> list[str] | None:
    lookup = getattr(ctx.registry, "advisories", None)
    if not callable(lookup) or ctx.advisory_lookups >= MAX_ADVISORY_LOOKUPS:
        return None
    ctx.advisory_lookups += 1
    try:
        found = lookup(name, version)
    except Exception:  # noqa: BLE001 - an advisory lookup never blocks remediation
        return None
    return found if isinstance(found, list) else None


def _prefer_clean(
    ctx: _Context, versions: Sequence[str], fixes: Callable[[str], bool], name: str | None = None
) -> str | None:
    """The lowest version that ``fixes`` the case and has no other known advisory.

    Falls back to the lowest fixing version when every checked one has advisories or the
    lookup is unavailable (offline), so the network never decides whether a fix exists.
    """
    package = name or ctx.name
    fixing = [v for v in versions if fixes(v)]
    skipped: list[str] = []
    for version in fixing[:MAX_ADVISORY_LOOKUPS]:
        found = _target_advisories(ctx, package, version)
        if found is None:
            break  # unknown: do not guess, keep the plain choice
        if not found:
            notes = [*skipped, f"OSV: no known advisory for {package} {version}"]
            ctx.advisory_notes.setdefault(version, notes)
            return version
        skipped.append(f"skipped {package} {version}: itself affected by {', '.join(found[:3])}")
    if not fixing:
        return None
    if skipped:
        ctx.advisory_notes.setdefault(
            fixing[0], [*skipped, f"no checked {package} version is free of advisories"]
        )
    return fixing[0]


def _later_versions(
    package: PackageVersions | None, current: str | None, *, verified: bool
) -> list[str]:
    """Ascending candidate versions above ``current``: published, stable and not deprecated."""
    if package is None:
        return []
    cur = npm_semver.parse(current) if current else None
    result = []
    for version in package.published():
        parsed = npm_semver.parse(version)
        meta = package.versions[version]
        if parsed is None or parsed.is_prerelease or (verified and meta.deprecated):
            continue
        if cur is not None and parsed <= cur:
            continue
        result.append(version)
    return result


def _osv_versions(ctx: _Context) -> list[str]:
    """Fixed versions named by the advisories, above the current version (unverified)."""
    fixed: set[str] = set()
    for d in ctx.details:
        fixed.update(d.fixed_versions)
        if d.recommended_fix:
            fixed.add(d.recommended_fix)
    cur = npm_semver.parse(ctx.current) if ctx.current else None
    ordered = npm_semver.sort_versions(sorted(fixed))
    return [
        v
        for v in ordered
        if (p := npm_semver.parse(v)) is not None
        and not p.is_prerelease
        and (cur is None or p > cur)
    ]


def _risk_reduction(ctx: _Context, fixed_ids: set[str]) -> float:
    """Max case score minus the max score of the findings that stay (re-assessed)."""
    scores = [ctx.assessments[f.id].score or 0.0 for f in ctx.findings if f.id in ctx.assessments]
    max_all = max(scores, default=0.0)
    remaining = [f for f in ctx.findings if f.id not in fixed_ids]
    if not remaining:
        return round(max_all, 1)
    rescored = assess(remaining, ctx.graph, ctx.code_index)
    return round(max(0.0, max_all - max((a.score or 0.0 for a in rescored), default=0.0)), 1)


def _jump_notes(from_version: str | None, to_version: str | None, label: str) -> list[str]:
    a = npm_semver.parse(from_version) if from_version else None
    b = npm_semver.parse(to_version) if to_version else None
    if a is None or b is None:
        return []
    if a.major != b.major:
        return [
            (
                f"major version jump {a.major}.x → {b.major}.x for {label}: breaking changes "
                "expected per semver"
            )
        ]
    if a.major == 0 and a.minor != b.minor:
        return [
            (
                f"0.x minor jump {a.major}.{a.minor} → {b.major}.{b.minor} for {label}: may break "
                "per semver (0.x releases carry no compatibility promise)"
            )
        ]
    return []


def _registry_notes(package: PackageVersions | None, version: str) -> tuple[list[str], list[str]]:
    """(compatibility notes, evidence) describing what the registry established."""
    if package is None:
        return ["no registry verification: version taken from OSV fixed versions"], []
    notes: list[str] = []
    if package.stale and package.fetched_at:
        notes.append(
            f"registry unreachable; version list from cache fetched "
            f"{package.fetched_at.date().isoformat()}"
        )
    return notes, [f"registry: {package.name} {version} published, not deprecated"]


# --- Candidate builders ------------------------------------------------------------------


def _upgrade(ctx: _Context, version: str, *, verified: bool) -> RemediationCandidate:
    remaining = ctx.still_affected(version)
    fixed = [f.id for f in ctx.findings if f not in remaining]
    notes = _jump_notes(ctx.current, version, ctx.name)
    reg_notes, reg_evidence = _registry_notes(ctx.package if verified else None, version)
    notes += reg_notes + ctx.advisory_notes.get(version, [])
    if remaining:
        ids = ", ".join(_vuln_id(f) for f in remaining)
        notes.append(f"partial fix: {ctx.name} {version} is still affected by {ids}")
    restore = None
    if ctx.spec is not None and ctx.manifest_path:
        new_spec = npm_semver.rewrite_spec(ctx.spec, version)
        notes.append(
            f'{ctx.manifest_path}: "{ctx.name}": "{ctx.spec}" → "{new_spec}" '
            "(lockfile regenerated in the sandbox)"
        )
        restore = f'restore "{ctx.name}": "{ctx.spec}" in {ctx.manifest_path}'
    return RemediationCandidate(
        id=candidate_id_for(ctx.case.fingerprint, RemediationActionType.UPGRADE, ctx.purl, version),
        case_id=ctx.case.id,
        finding_ids=[f.id for f in ctx.findings],
        action_type=RemediationActionType.UPGRADE,
        component=ctx.purl,
        from_version=ctx.current,
        to_version=version,
        manifest_path=ctx.manifest_path,
        fixes_finding_ids=fixed,
        semver_jump=semver_jump(ctx.current, version),
        compatibility_notes=notes,
        rollback=ctx.rollback(restore),
        expected_risk_reduction=_risk_reduction(ctx, set(fixed)),
        version_verified=verified,
        evidence=ctx.evidence(reg_evidence),
        strategy="direct",
    )


def _vuln_id(finding: Finding) -> str:
    d = finding.details
    return d.vulnerability_id if isinstance(d, VulnerabilityDetails) else finding.id


def _direct_upgrades(ctx: _Context) -> list[RemediationCandidate]:
    verified = ctx.package is not None
    versions = _later_versions(ctx.package, ctx.current, verified=True) if verified else []
    if not verified:
        versions = _osv_versions(ctx)
    cur = npm_semver.parse(ctx.current) if ctx.current else None

    def first(predicate: Callable[[str], bool]) -> str | None:
        return next((v for v in versions if predicate(v)), None)

    same_major = None
    if cur is not None:
        same_major = _prefer_clean(
            ctx,
            versions,
            lambda v: (
                (p := npm_semver.parse(v)) is not None
                and p.major == cur.major
                and not ctx.still_affected(v)
            ),
        )
    overall = _prefer_clean(ctx, versions, lambda v: not ctx.still_affected(v))
    picks = [v for v in (same_major, overall) if v is not None]
    # Partial fixes: the lowest version that resolves each finding on its own, so a reviewer
    # sees e.g. "4.2.2 fixes the critical advisory" next to "9.0.0 fixes all of them".
    partial: list[str] = []
    for finding in _by_score(ctx):
        d = finding.details
        if not isinstance(d, VulnerabilityDetails):
            continue
        version = first(lambda v, d=d: not is_affected(v, d))
        if version is None or version in picks or version in partial:
            continue
        if overall is not None and npm_semver.compare(version, overall) >= 0:
            continue
        partial.append(version)
    picks = list(dict.fromkeys(picks))
    partial = npm_semver.sort_versions(partial)[:MAX_PARTIAL_CANDIDATES]
    return [_upgrade(ctx, v, verified=verified) for v in [*picks, *partial]]


def _by_score(ctx: _Context) -> list[Finding]:
    def score(f: Finding) -> float:
        a = ctx.assessments.get(f.id)
        return a.score or 0.0 if a else 0.0

    return sorted(ctx.findings, key=lambda f: (-score(f), f.id))


def _direct_ancestors(ctx: _Context) -> list[Component]:
    if ctx.component is None:
        return []
    parents: dict[str, Component] = {}
    for path in ctx.graph.introduction_paths(ctx.component.ref, limit=20):
        if len(path) > 1:
            parents.setdefault(path[0].ref, path[0])
    return list(parents.values())


def _component_name(component: Component) -> str:
    return f"{component.group}/{component.name}" if component.group else component.name


def _parent_upgrade(
    ctx: _Context, parent: Component, all_parents: list[Component]
) -> RemediationCandidate | None:
    parent_name = _component_name(parent)
    child = ctx.package
    parent_pkg = ctx.fetch(parent_name)
    if child is None or parent_pkg is None or ctx.manifest is None:
        return None
    declared = find_dependency(ctx.manifest, parent_name)
    if declared is None:
        return None
    _, parent_spec = declared
    child_versions = _later_versions(child, None, verified=False)
    choice: tuple[str, str | None, str | None] | None = None
    for version in _later_versions(parent_pkg, parent.version, verified=True):
        child_range = parent_pkg.versions[version].dependencies.get(ctx.name)
        if child_range is None:
            choice = (version, None, None)  # this release no longer depends on the package
            break
        resolved = npm_semver.max_satisfying(child_versions, child_range)
        if resolved is not None and not ctx.still_affected(resolved):
            choice = (version, child_range, resolved)
            break
    if choice is None:
        return None
    version, child_range, resolved = choice
    others = [_component_name(p) for p in all_parents if p.ref != parent.ref]
    fixed = [f.id for f in ctx.findings] if not others else []
    notes = _jump_notes(parent.version, version, parent_name)
    if resolved is None:
        notes.append(f"{parent_name} {version} no longer depends on {ctx.name}")
    else:
        notes.append(
            f'{parent_name} {version} declares "{ctx.name}": "{child_range}", which resolves '
            f"to {ctx.name} {resolved} (not affected)"
        )
    if others:
        notes.append(
            f"{ctx.name} also enters through {', '.join(sorted(others))}; this upgrade alone "
            "does not remove it"
        )
    new_spec = npm_semver.rewrite_spec(parent_spec, version)
    notes.append(f'{ROOT_MANIFEST}: "{parent_name}": "{parent_spec}" → "{new_spec}"')
    if parent_pkg.stale:
        notes.append(f"registry unreachable; {parent_name} versions from cache")
    evidence = [f"registry: {parent_name} {version} published, not deprecated"]
    if resolved is not None:
        evidence.append(f"registry: {ctx.name} {resolved} published")
    key = f"{ctx.purl}|parent:{parent_name}"
    return RemediationCandidate(
        id=candidate_id_for(ctx.case.fingerprint, RemediationActionType.UPGRADE, key, version),
        case_id=ctx.case.id,
        finding_ids=[f.id for f in ctx.findings],
        action_type=RemediationActionType.UPGRADE,
        component=ctx.purl,
        from_version=parent.version,
        to_version=version,
        manifest_path=ROOT_MANIFEST,
        fixes_finding_ids=fixed,
        semver_jump=semver_jump(parent.version, version),
        compatibility_notes=notes,
        rollback=ctx.rollback(f'restore "{parent_name}": "{parent_spec}" in {ROOT_MANIFEST}'),
        expected_risk_reduction=_risk_reduction(ctx, set(fixed)),
        version_verified=True,
        evidence=ctx.evidence(evidence),
        strategy="parent",
        target_package=parent_name,
    )


def _override(ctx: _Context, parents: list[Component]) -> RemediationCandidate | None:
    verified = ctx.package is not None
    versions = (
        _later_versions(ctx.package, ctx.current, verified=True) if verified else _osv_versions(ctx)
    )
    version = _prefer_clean(ctx, versions, lambda v: not ctx.still_affected(v))
    if version is None or ctx.manifest is None:
        return None
    notes = [
        (
            f'{ROOT_MANIFEST}: "overrides": {{"{ctx.name}": "{version}"}} forces {ctx.name} '
            f"{version} for every dependent"
        ),
        *_jump_notes(ctx.current, version, ctx.name),
    ]
    for parent in parents:
        parent_name = _component_name(parent)
        parent_pkg = ctx.fetch(parent_name) if verified else None
        meta = parent_pkg.versions.get(parent.version or "") if parent_pkg else None
        declared = meta.dependencies.get(ctx.name) if meta else None
        if declared is not None and not npm_semver.satisfies(version, declared):
            notes.append(
                f'{parent_name} {parent.version} declares "{ctx.name}": "{declared}"; the '
                f"override goes outside that range"
            )
    reg_notes, reg_evidence = _registry_notes(ctx.package if verified else None, version)
    notes += reg_notes + ctx.advisory_notes.get(version, [])
    fixed = [f.id for f in ctx.findings]
    return RemediationCandidate(
        id=candidate_id_for(ctx.case.fingerprint, RemediationActionType.PIN, ctx.purl, version),
        case_id=ctx.case.id,
        finding_ids=fixed,
        action_type=RemediationActionType.PIN,
        component=ctx.purl,
        from_version=ctx.current,
        to_version=version,
        manifest_path=ROOT_MANIFEST,
        fixes_finding_ids=fixed,
        semver_jump=semver_jump(ctx.current, version),
        compatibility_notes=notes,
        rollback=ctx.rollback(f'remove "{ctx.name}" from "overrides" in {ROOT_MANIFEST}'),
        expected_risk_reduction=_risk_reduction(ctx, set(fixed)),
        version_verified=verified,
        evidence=ctx.evidence(reg_evidence),
        strategy="override",
    )


def _script_mentions(manifest: Mapping[str, Any], name: str) -> list[str]:
    scripts = manifest.get("scripts")
    if not isinstance(scripts, dict):
        return []
    pattern = re.compile(rf"(?<![\w@/.-]){re.escape(name)}(?![\w-])")
    return sorted(k for k, v in scripts.items() if isinstance(v, str) and pattern.search(v))


def _used_in_code(ctx: _Context, index: CodeIndex) -> bool:
    ref = ctx.component.ref if ctx.component else None
    prefix = f"{ctx.name}/"
    for imp in index.imports:
        if imp.package == ctx.name or (ref and imp.component_ref == ref):
            return True
        if imp.module == ctx.name or imp.module.startswith(prefix):
            return True
    return any(
        call.package == ctx.name or (ref is not None and call.component_ref == ref)
        for call in index.calls
    )


def _remove(ctx: _Context) -> RemediationCandidate | None:
    index = ctx.code_index
    if (
        index is None
        or ctx.manifest is None
        or ctx.spec is None
        or ctx.section is None
        or not ctx.manifest_path
    ):
        return None
    if _used_in_code(ctx, index) or _script_mentions(ctx.manifest, ctx.name):
        return None
    fixed = [f.id for f in ctx.findings]
    notes = [
        f"no import or call of {ctx.name} in the code index ({len(index.files)} files indexed)",
        f"{ctx.name} is not referenced in {ctx.manifest_path} scripts",
        "not checked: configuration files, dynamic requires and CLI binaries of the package",
        f'{ctx.manifest_path}: remove "{ctx.name}": "{ctx.spec}" from "{ctx.section}"',
    ]
    return RemediationCandidate(
        id=candidate_id_for(ctx.case.fingerprint, RemediationActionType.REMOVE, ctx.purl, None),
        case_id=ctx.case.id,
        finding_ids=fixed,
        action_type=RemediationActionType.REMOVE,
        component=ctx.purl,
        from_version=ctx.current,
        manifest_path=ctx.manifest_path,
        fixes_finding_ids=fixed,
        compatibility_notes=notes,
        rollback=ctx.rollback(
            f'restore "{ctx.name}": "{ctx.spec}" in "{ctx.section}" of {ctx.manifest_path}'
        ),
        expected_risk_reduction=_risk_reduction(ctx, set(fixed)),
        evidence=ctx.evidence([f"code-index: no usage of {ctx.name}"]),
    )


def _non_code(ctx: _Context, action: RemediationActionType) -> RemediationCandidate:
    base = npm_purl(ctx.name)
    if action is RemediationActionType.BLOCK:
        notes = [
            f"adds {base} to the Guardian policy denylist; no code change",
            "does not resolve the findings; future scans flag any use of the package",
        ]
        rollback = f"remove {base} from the Guardian denylist"
    else:
        notes = ["hands the case to a security reviewer; no code change"]
        rollback = "no change to revert"
    return RemediationCandidate(
        id=candidate_id_for(ctx.case.fingerprint, action, base, None),
        case_id=ctx.case.id,
        finding_ids=[f.id for f in ctx.findings],
        action_type=action,
        component=ctx.purl,
        from_version=ctx.current,
        compatibility_notes=notes,
        rollback=rollback,
        evidence=ctx.evidence(),
    )


# --- Entry point -------------------------------------------------------------------------


def generate_candidates(  # noqa: PLR0913, PLR0917 - the inputs a candidate is computed from
    case: RemediationCase,
    findings: Sequence[Finding],
    sbom: Sbom | None,
    graph: DependencyGraph,
    code_index: CodeIndex | None,
    risk_assessments: Mapping[str, RiskAssessment] | Sequence[RiskAssessment],
    registry: RegistryLike | None,
    repo_root: Path | str,
    *,
    worktree_root: str | Path | None = None,
) -> list[RemediationCandidate]:
    """Candidates for one npm package case (all ``findings`` concern the same package)."""
    vulns = [f for f in findings if is_npm_finding(f)]
    assessments = (
        dict(risk_assessments)
        if isinstance(risk_assessments, Mapping)
        else {a.finding_id: a for a in risk_assessments}
    )
    if any(f.id not in assessments for f in vulns):
        assessments.update({a.finding_id: a for a in assess(vulns, graph, code_index)})
    first = vulns[0].details if vulns else None
    name = first.package if isinstance(first, VulnerabilityDetails) else case.title
    current = first.version if isinstance(first, VulnerabilityDetails) else None
    ctx = _Context(
        case=case,
        name=name,
        current=current,
        purl=npm_purl(name, current),
        findings=vulns,
        graph=graph,
        code_index=code_index,
        assessments=assessments,
        registry=registry,
        repo_root=Path(repo_root),
        worktree_root=str(worktree_root or DEFAULT_WORKTREE_ROOT),
    )
    if not vulns:
        return [_non_code(ctx, RemediationActionType.ESCALATE)]
    ctx.component = _component(vulns, graph, sbom)
    if ctx.component is not None and ctx.component.purl:
        ctx.purl = ctx.component.purl
    _load_manifest(ctx)
    ctx.package = ctx.fetch(name)

    candidates: list[RemediationCandidate] = []
    depth = graph.depth(ctx.component.ref) if ctx.component else None
    direct = ctx.spec is not None or depth == 1
    if direct:
        candidates += _direct_upgrades(ctx)
    else:
        parents = _direct_ancestors(ctx)
        candidates += [c for p in parents if (c := _parent_upgrade(ctx, p, parents)) is not None]
        if (override := _override(ctx, parents)) is not None:
            candidates.append(override)
    if direct and (remove := _remove(ctx)) is not None:
        candidates.append(remove)
    candidates.append(_non_code(ctx, RemediationActionType.BLOCK))
    candidates.append(_non_code(ctx, RemediationActionType.ESCALATE))
    return list({c.id: c for c in candidates}.values())


def _component(
    findings: list[Finding], graph: DependencyGraph, sbom: Sbom | None
) -> Component | None:
    refs = [f.component_ref for f in findings if f.component_ref]
    for ref in refs:
        try:
            return graph.component(component_node(ref))
        except KeyError:
            continue
    if sbom is not None:
        by_ref = {c.ref: c for c in sbom.components}
        for ref in refs:
            if ref in by_ref:
                return by_ref[ref]
    return None


def _load_manifest(ctx: _Context) -> None:
    declared = [
        p for p in (ctx.component.declared_in if ctx.component else []) if p.endswith(ROOT_MANIFEST)
    ]
    for path in [*declared, ROOT_MANIFEST]:
        data = read_manifest(ctx.repo_root, path)
        if data is None:
            continue
        if ctx.manifest is None:
            ctx.manifest, ctx.manifest_path = data, path
        found = find_dependency(data, ctx.name)
        if found is not None:
            ctx.manifest, ctx.manifest_path = data, path
            ctx.section, ctx.spec = found
            return

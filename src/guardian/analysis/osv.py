"""Known-vulnerability detection with OSV-Scanner.

OSV-Scanner establishes the facts: which package versions match which advisories. Guardian
scans its own SBOM so every match maps onto an exact component in the dependency graph, and
falls back to scanning the repository's lockfiles when no SBOM exists.

Privacy: OSV-Scanner sends package names and versions (never source code) to api.osv.dev.
"""

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from packageurl import PackageURL
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from guardian.analysis.base import AnalysisResult, decode_tool_output, stable_id, summarize
from guardian.core.models import (
    AffectedRange,
    Component,
    Evidence,
    EvidenceKind,
    Finding,
    FindingKind,
    Sbom,
    Severity,
    VulnerabilityDetails,
)
from guardian.execution.runner import ToolRunner
from guardian.remediation import npm_semver

OSV_SCANNER = "osv-scanner"
# 0: no vulnerabilities, 1: vulnerabilities found, 128: no packages found.
OSV_OK_EXIT_CODES = frozenset({0, 1, 128})
MAX_REFERENCES = 10

_DB_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


class _Raw(BaseModel):
    model_config = ConfigDict(extra="ignore")


class OsvSeverity(_Raw):
    type: str
    score: str


class OsvEvent(_Raw):
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None


class OsvRange(_Raw):
    type: str
    events: list[OsvEvent] = Field(default_factory=list)


class OsvAffectedPackage(_Raw):
    name: str | None = None
    ecosystem: str | None = None


class OsvAffected(_Raw):
    package: OsvAffectedPackage | None = None
    ranges: list[OsvRange] = Field(default_factory=list)


class OsvReference(_Raw):
    type: str | None = None
    url: str


class OsvVulnerability(_Raw):
    id: str
    aliases: list[str] = Field(default_factory=list)
    summary: str | None = None
    severity: list[OsvSeverity] = Field(default_factory=list)
    affected: list[OsvAffected] = Field(default_factory=list)
    references: list[OsvReference] = Field(default_factory=list)
    published: datetime | None = None
    database_specific: dict[str, Any] = Field(default_factory=dict)


class OsvGroup(_Raw):
    ids: list[str]
    aliases: list[str] = Field(default_factory=list)
    max_severity: str | None = None


class OsvPackageInfo(_Raw):
    name: str
    version: str | None = None
    ecosystem: str | None = None
    purl: str | None = None


class OsvPackage(_Raw):
    package: OsvPackageInfo
    groups: list[OsvGroup] = Field(default_factory=list)
    vulnerabilities: list[OsvVulnerability] = Field(default_factory=list)


class OsvSource(_Raw):
    path: str
    type: str


class OsvResult(_Raw):
    source: OsvSource
    packages: list[OsvPackage] = Field(default_factory=list)


class OsvOutput(_Raw):
    results: list[OsvResult] = Field(default_factory=list)


def _bare_purl(purl: str | None) -> str | None:
    """purl without qualifiers/subpath; osv-scanner adds e.g. ``?source=PUBLIC_REGISTRY``."""
    if not purl:
        return None
    try:
        p = PackageURL.from_string(purl)
    except ValueError:
        return None
    return PackageURL(
        type=p.type, namespace=p.namespace, name=p.name, version=p.version
    ).to_string()


class ComponentIndex:
    """Map OSV package identities onto SBOM component refs."""

    def __init__(self, sbom: Sbom | None) -> None:
        self.by_purl: dict[str, Component] = {}
        self.by_name: dict[tuple[str, str | None], Component] = {}
        for component in sbom.components if sbom else []:
            if bare := _bare_purl(component.purl):
                self.by_purl.setdefault(bare, component)
            full = f"{component.group}/{component.name}" if component.group else component.name
            self.by_name.setdefault((full.lower(), component.version), component)

    def lookup(self, package: OsvPackageInfo) -> Component | None:
        if (bare := _bare_purl(package.purl)) and bare in self.by_purl:
            return self.by_purl[bare]
        return self.by_name.get((package.name.lower(), package.version))


def _severity(group: OsvGroup, vulns: list[OsvVulnerability]) -> tuple[Severity, float | None]:
    try:
        score = float(group.max_severity) if group.max_severity else None
    except ValueError:
        score = None
    if score is not None:
        return Severity.from_cvss(score), score
    labels = [_DB_SEVERITY.get(str(v.database_specific.get("severity", "")).upper()) for v in vulns]
    known = [s for s in labels if s is not None]
    return (max(known, key=lambda s: s.rank), None) if known else (Severity.UNKNOWN, None)


def _fixed_versions(package: OsvPackageInfo, vulns: list[OsvVulnerability]) -> list[str]:
    fixed: set[str] = set()
    for vuln in vulns:
        for affected in vuln.affected:
            name = affected.package.name if affected.package else None
            if name and name.lower() != package.name.lower():
                continue
            fixed.update(e.fixed for r in affected.ranges for e in r.events if e.fixed)
    return sorted(fixed)


def version_key(version: str) -> tuple[tuple[int, int, str], ...]:
    """Tolerant ordering for semver/PEP 440-like versions.

    Each token is (rank, number, text): numbers rank 1, letters -1 and the end of the version
    0, so a pre-release sorts below its release (1.0.0-beta < 1.0.0) while an extra numeric
    part sorts above it (1.0.0 < 1.0.0.1).
    """
    tokens = [
        (1, int(token), "") if token.isdigit() else (-1, 0, token.lower())
        for token in re.findall(r"\d+|[A-Za-z]+", version)
    ]
    return (*tokens, (0, 0, ""))


VERSIONED_RANGE_TYPES = frozenset({"SEMVER", "ECOSYSTEM"})


def _affected_ranges(package: OsvPackageInfo, vulns: list[OsvVulnerability]) -> list[AffectedRange]:
    """Every SEMVER/ECOSYSTEM interval of the package across the group's advisories."""
    ranges: list[AffectedRange] = []
    for vuln in vulns:
        for affected in vuln.affected:
            name = affected.package.name if affected.package else None
            if name and name.lower() != package.name.lower():
                continue
            for rng in affected.ranges:
                if rng.type.upper() not in VERSIONED_RANGE_TYPES:
                    continue
                introduced: str | None = None
                is_open = False
                for event in rng.events:
                    if event.introduced is not None:
                        if is_open:  # two "introduced" in a row: the first stays open-ended
                            ranges.append(AffectedRange(introduced=introduced))
                        introduced, is_open = event.introduced, True
                    elif is_open and (event.fixed or event.last_affected):
                        ranges.append(
                            AffectedRange(
                                introduced=introduced,
                                fixed=event.fixed,
                                last_affected=None if event.fixed else event.last_affected,
                            )
                        )
                        introduced, is_open = None, False
                if is_open:
                    ranges.append(AffectedRange(introduced=introduced))
    unique = {(r.introduced, r.fixed, r.last_affected): r for r in ranges}
    return list(unique.values())


def _version_cmp(a: str, b: str, ecosystem: str | None) -> int:
    """npm semver precedence when both versions parse (npm advisories), else ``version_key``."""
    if (ecosystem or "").lower() in {"npm", ""}:
        left, right = npm_semver.parse(a), npm_semver.parse(b)
        if left is not None and right is not None:
            return (left > right) - (left < right)
    ka, kb = version_key(a), version_key(b)
    return (ka > kb) - (ka < kb)


def _in_range(version: str, rng: AffectedRange, ecosystem: str | None) -> bool:
    if (
        rng.introduced not in {None, "0"}
        and _version_cmp(version, rng.introduced or "0", ecosystem) < 0
    ):
        return False
    if rng.fixed is not None:
        return _version_cmp(version, rng.fixed, ecosystem) < 0
    if rng.last_affected is not None:
        return _version_cmp(version, rng.last_affected, ecosystem) <= 0
    return True


def _same_branch(a: str, b: str) -> bool:
    """Same major (or same 0.minor for 0.x), the branch a fixed release usually patches."""
    left, right = version_key(a), version_key(b)
    if not left or not right or left[0] != right[0]:
        return False
    if left[0] == (1, 0, ""):  # 0.x: the minor is the compatibility line
        return len(left) > 1 and len(right) > 1 and left[1] == right[1]
    return True


def is_affected(version: str, details: VulnerabilityDetails) -> bool:
    """Whether the advisory affects ``version`` of the finding's package.

    Uses the OSV affected ranges when the finding carries them. Older stored findings only have
    the fixed releases, so the fallback is conservative: a version counts as fixed only when it
    is at or above a fixed release on its own branch (same major, or same 0.minor), or at or
    above the highest fixed release. Without any fixed release every version is affected.
    """
    eco = details.ecosystem
    if details.affected_ranges:
        return any(_in_range(version, r, eco) for r in details.affected_ranges)
    if details.version is not None and _version_cmp(version, details.version, eco) == 0:
        return True
    fixed = list(details.fixed_versions)
    if details.recommended_fix and details.recommended_fix not in fixed:
        fixed.append(details.recommended_fix)
    if not fixed:
        return True
    highest = max(fixed, key=version_key)
    if _version_cmp(version, highest, eco) >= 0:
        return False
    return not any(_same_branch(version, f) and _version_cmp(version, f, eco) >= 0 for f in fixed)


def _recommended_fix(package: OsvPackageInfo, vulns: list[OsvVulnerability]) -> str | None:
    """Lowest fix across all advisories, each taken from the range containing the version."""
    if not package.version:
        return None
    current = version_key(package.version)
    needed: list[str] = []
    for vuln in vulns:
        candidates = []
        for affected in vuln.affected:
            name = affected.package.name if affected.package else None
            if name and name.lower() != package.name.lower():
                continue
            for rng in affected.ranges:
                if rng.type == "GIT":
                    continue
                introduced: tuple | None = None
                for event in rng.events:
                    if event.introduced is not None:
                        introduced = version_key(event.introduced)
                    elif event.fixed and introduced is not None:
                        if introduced <= current < version_key(event.fixed):
                            candidates.append(event.fixed)
                        introduced = None
        if candidates:
            needed.append(min(candidates, key=version_key))
    # Every advisory must be fixed, so the recommendation is the highest of the per-advisory
    # minimum fixes.
    return max(needed, key=version_key) if needed else None


def _display_id(group: OsvGroup) -> str:
    """Prefer the CVE id people search for; fall back to the first OSV id."""
    cves = sorted(a for a in [*group.aliases, *group.ids] if a.startswith("CVE-"))
    return cves[0] if cves else group.ids[0]


def parse_osv_output(data: str | bytes, sbom: Sbom | None) -> tuple[list[Finding], list[str]]:
    output = OsvOutput.model_validate(json.loads(decode_tool_output(data)))
    index = ComponentIndex(sbom)
    findings: dict[str, Finding] = {}
    unmatched = 0
    for result in output.results:
        for package in result.packages:
            component = index.lookup(package.package)
            if component is None and sbom is not None:
                unmatched += 1
            by_id = {v.id: v for v in package.vulnerabilities}
            groups = package.groups or [
                OsvGroup(ids=[v.id], aliases=v.aliases) for v in by_id.values()
            ]
            for group in groups:
                vulns = [by_id[i] for i in group.ids if i in by_id]
                if not vulns:
                    continue
                finding = _finding(package.package, component, group, vulns, result.source)
                findings.setdefault(finding.id, finding)
    warnings = []
    if unmatched:
        warnings.append(
            f"{unmatched} vulnerable package(s) reported by OSV-Scanner are not in the SBOM"
        )
    ordered = sorted(findings.values(), key=lambda f: (-f.severity.rank, f.title))
    return ordered, warnings


def _finding(
    package: OsvPackageInfo,
    component: Component | None,
    group: OsvGroup,
    vulns: list[OsvVulnerability],
    source: OsvSource,
) -> Finding:
    severity, score = _severity(group, vulns)
    display = _display_id(group)
    primary = vulns[0]
    aliases = sorted(
        {*group.ids, *group.aliases, *(a for v in vulns for a in v.aliases)} - {display}
    )
    cwes = sorted({c for v in vulns for c in v.database_specific.get("cwe_ids", []) or []})
    fixed = _fixed_versions(package, vulns)
    name_version = f"{package.name}@{package.version}" if package.version else package.name
    summary = primary.summary or display

    evidence = [
        Evidence(
            kind=EvidenceKind.TOOL_MATCH,
            tool=OSV_SCANNER,
            summary=f"OSV-Scanner matched {name_version} against {', '.join(group.ids)}",
        ),
        Evidence(
            kind=EvidenceKind.ADVISORY,
            tool=OSV_SCANNER,
            summary=summary,
            url=f"https://osv.dev/vulnerability/{group.ids[0]}",
        ),
    ]
    evidence += [
        Evidence(
            kind=EvidenceKind.MANIFEST,
            tool=OSV_SCANNER,
            summary=f"{name_version} is declared in {path}",
            path=path,
        )
        for path in (component.declared_in if component else [])
    ]
    if source.type == "lockfile":
        evidence.append(
            Evidence(
                kind=EvidenceKind.MANIFEST,
                tool=OSV_SCANNER,
                summary=f"Found in lockfile {Path(source.path).name}",
            )
        )

    return Finding(
        id=stable_id(
            FindingKind.VULNERABILITY,
            package.ecosystem,
            package.name,
            package.version,
            group.ids[0],
        ),
        kind=FindingKind.VULNERABILITY,
        title=f"{display} in {name_version}",
        severity=severity,
        tool=OSV_SCANNER,
        component_ref=component.ref if component else None,
        details=VulnerabilityDetails(
            vulnerability_id=display,
            summary=primary.summary,
            aliases=aliases,
            package=package.name,
            version=package.version,
            ecosystem=package.ecosystem,
            purl=_bare_purl(package.purl) or (component.purl if component else None),
            cvss_score=score,
            cvss_vectors=sorted({s.score for v in vulns for s in v.severity}),
            cwe_ids=cwes,
            fixed_versions=fixed,
            recommended_fix=_recommended_fix(package, vulns),
            published=min((v.published for v in vulns if v.published), default=None),
            references=[r.url for r in primary.references[:MAX_REFERENCES]],
            affected_ranges=_affected_ranges(package, vulns),
        ),
        evidence=evidence,
    )


class OsvScanner:
    def __init__(self, runner: ToolRunner, timeout_seconds: float | None = None) -> None:
        self.runner = runner
        self.timeout_seconds = timeout_seconds

    def scan(
        self,
        repo_root: Path,
        work_dir: Path,
        sbom: Sbom | None,
        raw_sbom: bytes | None,
        excluded_dirs: frozenset[str] = frozenset(),
    ) -> AnalysisResult:
        output = work_dir / "osv.json"
        # --no-resolve: never resolve manifests over the network; lockfiles/SBOM are the truth.
        # --no-call-analysis=all: Rust call analysis runs build scripts from the repository.
        args = [
            "scan",
            "source",
            "--format",
            "json",
            "--output-file",
            str(output),
            "--no-resolve",
            "--no-call-analysis=all",
            "--verbosity",
            "error",
        ]
        if raw_sbom is not None and sbom is not None:
            bom = work_dir / "guardian.cdx.json"  # osv-scanner requires the *.cdx.json name
            bom.write_bytes(raw_sbom)
            args += ["--lockfile", str(bom)]
        else:
            args += ["--recursive", "--allow-no-lockfiles"]
            for name in sorted(excluded_dirs):
                args += ["--x-exclude", name]
            args.append(str(repo_root))

        result = self.runner.run(
            OSV_SCANNER, args, cwd=work_dir, timeout_seconds=self.timeout_seconds
        )
        if not output.is_file():
            return AnalysisResult(tool_run=summarize(result, OSV_OK_EXIT_CODES))
        try:
            findings, warnings = parse_osv_output(output.read_bytes(), sbom)
        except (ValidationError, ValueError) as exc:
            run = summarize(result, (), error=f"Unreadable OSV-Scanner output: {exc}"[:500])
            return AnalysisResult(tool_run=run)
        return AnalysisResult(
            tool_run=summarize(result, OSV_OK_EXIT_CODES), findings=findings, warnings=warnings
        )

"""CycloneDX JSON parsing and normalization into Guardian's ``Sbom`` model.

The raw models below describe only the subset of CycloneDX that Guardian uses and ignore
everything else, so they accept spec versions 1.4 through 1.7.
"""

import os
from collections import defaultdict
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from packageurl import PackageURL
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from guardian.adapters.base import normalize_package_name
from guardian.core.exceptions import GuardianError
from guardian.core.models import (
    Component,
    DependencyEdge,
    DependencyScope,
    DirectSource,
    Ecosystem,
    Sbom,
)

PURL_ECOSYSTEMS: dict[str, Ecosystem] = {
    "pypi": Ecosystem.PYTHON,
    "npm": Ecosystem.NODE,
    "maven": Ecosystem.JAVA,
    "docker": Ecosystem.CONTAINER,
    "oci": Ecosystem.CONTAINER,
}

# CycloneDX properties that carry the manifest a component was found in.
SOURCE_FILE_PROPERTIES = frozenset({"SrcFile", "cdx:src:file"})


class SbomParseError(GuardianError):
    """The SBOM is not valid CycloneDX JSON."""


class _Raw(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)


class CdxLicense(_Raw):
    id: str | None = None
    name: str | None = None


class CdxLicenseChoice(_Raw):
    license: CdxLicense | None = None
    expression: str | None = None


class CdxProperty(_Raw):
    name: str
    value: str | None = None


class CdxComponent(_Raw):
    bom_ref: str | None = Field(default=None, alias="bom-ref")
    type: str = "library"
    name: str
    group: str | None = None
    version: str | None = None
    purl: str | None = None
    scope: str | None = None
    licenses: list[CdxLicenseChoice] = Field(default_factory=list)
    properties: list[CdxProperty] = Field(default_factory=list)
    components: list["CdxComponent"] = Field(default_factory=list)

    @property
    def ref(self) -> str:
        if self.bom_ref:
            return self.bom_ref
        if self.purl:
            return self.purl
        prefix = f"{self.group}:" if self.group else ""
        return f"{prefix}{self.name}@{self.version or ''}"


class CdxDependency(_Raw):
    ref: str
    depends_on: list[str] = Field(default_factory=list, alias="dependsOn")


class CdxMetadata(_Raw):
    component: CdxComponent | None = None
    tools: Any = None


class CdxBom(_Raw):
    bom_format: Literal["CycloneDX"] = Field(alias="bomFormat")
    spec_version: str = Field(alias="specVersion")
    metadata: CdxMetadata | None = None
    components: list[CdxComponent] = Field(default_factory=list)
    dependencies: list[CdxDependency] = Field(default_factory=list)


def _generator(tools: object) -> str:
    """Tool name/version; ``tools`` is a list in CycloneDX 1.4 and an object from 1.5."""
    entries = tools.get("components", []) if isinstance(tools, dict) else tools
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, dict) and entry.get("name"):
                return " ".join(str(entry[k]) for k in ("name", "version") if entry.get(k))
    return "unknown"


def _flatten(components: list[CdxComponent]) -> list[CdxComponent]:
    flat: list[CdxComponent] = []
    stack = list(reversed(components))
    while stack:
        component = stack.pop()
        flat.append(component)
        stack.extend(reversed(component.components))
    return flat


def _licenses(component: CdxComponent) -> list[str]:
    found = []
    for choice in component.licenses:
        if choice.expression:
            found.append(choice.expression)
        elif choice.license and (choice.license.id or choice.license.name):
            found.append(choice.license.id or choice.license.name or "")
    return sorted(set(found))


def _scope(value: str | None) -> DependencyScope:
    try:
        return DependencyScope(value) if value else DependencyScope.UNKNOWN
    except ValueError:
        return DependencyScope.UNKNOWN


def normalize_source_path(value: str, root: Path, manifests: set[str]) -> str | None:
    """Map a cdxgen ``SrcFile`` value onto one of the repository's known manifests.

    cdxgen reports absolute paths, paths relative to its working directory, or paths relative
    to the temp directory, so the value is matched against known manifests rather than trusted.
    """
    posix = value.replace("\\", "/")
    if os.path.isabs(value):  # noqa: PTH117 - value may be a foreign-OS path string
        root_norm = os.path.normcase(str(root)) + os.sep
        value_norm = os.path.normcase(os.path.normpath(value))
        if not value_norm.startswith(root_norm):
            return None
        posix = os.path.normpath(value)[len(root_norm) :].replace("\\", "/")
        return posix if posix in manifests else None
    if posix in manifests:
        return posix
    suffix_matches = [m for m in manifests if posix.endswith("/" + m)]
    return max(suffix_matches, key=len) if suffix_matches else None


def _normalize_component(
    raw: CdxComponent, root: Path, manifests: set[str], *, direct: bool | None
) -> Component:
    purl_type = _purl_type(raw)
    declared = {
        path
        for prop in raw.properties
        if prop.name in SOURCE_FILE_PROPERTIES and prop.value
        if (path := normalize_source_path(prop.value, root, manifests))
    }
    return Component(
        ref=raw.ref,
        name=raw.name,
        group=raw.group or None,
        version=raw.version or None,
        purl=raw.purl or None,
        purl_type=purl_type,
        ecosystem=PURL_ECOSYSTEMS.get(purl_type or ""),
        component_type=raw.type,
        scope=_scope(raw.scope),
        licenses=_licenses(raw),
        declared_in=sorted(declared),
        direct=direct,
    )


def parse_cyclonedx(
    data: str | bytes,
    *,
    repo_root: Path,
    manifests: set[str],
    declared: Mapping[Ecosystem, set[str]] | None = None,
) -> Sbom:
    """Parse CycloneDX JSON into a normalized ``Sbom``.

    ``manifests`` are the repository-relative manifest paths from the profile; component
    source paths are only kept when they resolve to one of them. ``declared`` holds the
    normalized dependency names Guardian parsed from those manifests, per ecosystem.
    """
    try:
        bom = CdxBom.model_validate_json(data)
    except ValidationError as exc:
        msg = f"Invalid CycloneDX document: {exc.error_count()} validation error(s)"
        raise SbomParseError(msg) from exc

    warnings: list[str] = []
    root = bom.metadata.component if bom.metadata else None
    root_ref = root.ref if root else None

    raw_components: dict[str, CdxComponent] = {}
    duplicates = 0
    for component in _flatten(bom.components):
        if component.ref == root_ref:
            continue
        if component.ref in raw_components:
            duplicates += 1
            continue
        raw_components[component.ref] = component
    if duplicates:
        warnings.append(f"{duplicates} duplicate component reference(s) ignored")

    known = set(raw_components) | ({root_ref} if root_ref else set())
    edges: set[tuple[str, str]] = set()
    dangling = 0
    for dependency in bom.dependencies:
        for target in dependency.depends_on:
            if dependency.ref in known and target in known and target != dependency.ref:
                edges.add((dependency.ref, target))
            else:
                dangling += 1
    if dangling:
        warnings.append(f"{dangling} dependency reference(s) point to unknown components")

    direct_refs, source = _direct_dependencies(root_ref, raw_components, edges, declared or {})
    if source is DirectSource.GRAPH_INFERENCE:
        warnings.append(
            "Neither the SBOM nor the manifests identify direct dependencies; inferred "
            f"{len(direct_refs)} from the dependency graph (packages that are both direct and "
            "transitive are missed)"
        )
    if root_ref:
        # Make the root's direct edges explicit so graph traversal starts from the repository.
        edges |= {(root_ref, ref) for ref in direct_refs}

    known = source is not DirectSource.UNKNOWN
    components = [
        _normalize_component(
            raw, repo_root, manifests, direct=(ref in direct_refs) if known else None
        )
        for ref, raw in sorted(raw_components.items())
    ]
    return Sbom(
        spec_version=bom.spec_version,
        generator=_generator(bom.metadata.tools if bom.metadata else None),
        root_ref=root_ref,
        components=components,
        edges=[DependencyEdge(source=s, target=t) for s, t in sorted(edges)],
        direct_source=source,
        warnings=warnings,
    )


def _purl_type(raw: CdxComponent) -> str | None:
    if not raw.purl:
        return None
    try:
        return PackageURL.from_string(raw.purl).type
    except ValueError:
        return None


def _qualified_name(raw: CdxComponent, ecosystem: Ecosystem) -> str:
    """The name a manifest would use: ``@scope/pkg`` for npm, ``group:artifact`` for Maven."""
    if raw.group and ecosystem is Ecosystem.NODE:
        return normalize_package_name(f"{raw.group}/{raw.name}")
    if raw.group and ecosystem is Ecosystem.JAVA:
        return normalize_package_name(f"{raw.group}:{raw.name}")
    return normalize_package_name(raw.name)


def _direct_dependencies(
    root_ref: str | None,
    components: dict[str, CdxComponent],
    edges: set[tuple[str, str]],
    declared: Mapping[Ecosystem, set[str]],
) -> tuple[set[str], DirectSource]:
    from_root = {t for s, t in edges if s == root_ref} if root_ref else set()
    from_manifests = set()
    for ref, raw in components.items():
        ecosystem = PURL_ECOSYSTEMS.get(_purl_type(raw) or "")
        if ecosystem and _qualified_name(raw, ecosystem) in declared.get(ecosystem, set()):
            from_manifests.add(ref)

    if from_root and from_manifests:
        return from_root | from_manifests, DirectSource.SBOM_AND_MANIFEST
    if from_root:
        return from_root, DirectSource.SBOM
    if from_manifests:
        return from_manifests, DirectSource.MANIFEST
    if not edges:
        return set(), DirectSource.UNKNOWN
    indegree: dict[str, int] = defaultdict(int)
    for _, target in edges:
        indegree[target] += 1
    return {ref for ref in components if indegree[ref] == 0}, DirectSource.GRAPH_INFERENCE

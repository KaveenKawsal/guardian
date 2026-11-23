"""Shared indexes for import resolution: repository layout and SBOM/manifest packages."""

from collections import deque
from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass, field
from typing import NamedTuple

from guardian.adapters.base import normalize_package_name
from guardian.core.models import Component, Ecosystem, ImportTarget, Sbom

_PURL_ECOSYSTEMS = {"pypi": Ecosystem.PYTHON, "npm": Ecosystem.NODE}
_UNKNOWN_DEPTH = 1 << 30


class Resolution(NamedTuple):
    target: ImportTarget
    target_path: str | None = None
    package: str | None = None
    component_ref: str | None = None


UNRESOLVED = Resolution(ImportTarget.UNRESOLVED)


def clean_path(path: str) -> str:
    """Repository-relative POSIX form: no backslashes, no leading './' or '/'."""
    path = path.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path.lstrip("/")


def parent_dir(path: str) -> str:
    return path.rpartition("/")[0]


def join(*parts: str) -> str:
    return "/".join(p for p in parts if p)


@dataclass(frozen=True)
class RepoLayout:
    files: frozenset[str]
    dirs: frozenset[str]
    """Every ancestor directory of a repository file (the root '' excluded)."""
    py_dirs: frozenset[str]
    """Directories containing a Python file at any depth (namespace-package candidates)."""
    top_dirs: frozenset[str]

    @classmethod
    def build(cls, repo_files: Iterable[str]) -> "RepoLayout":
        files: set[str] = set()
        dirs: set[str] = set()
        py_dirs: set[str] = set()
        for raw in repo_files:
            path = clean_path(str(raw))
            if not path or path in files:
                continue
            files.add(path)
            is_py = path.endswith((".py", ".pyi"))
            directory = parent_dir(path)
            while directory and (directory not in dirs or (is_py and directory not in py_dirs)):
                dirs.add(directory)
                if is_py:
                    py_dirs.add(directory)
                directory = parent_dir(directory)
        top = {d for d in dirs if "/" not in d}
        return cls(frozenset(files), frozenset(dirs), frozenset(py_dirs), frozenset(top))


def _component_ecosystem(component: Component) -> Ecosystem | None:
    if component.ecosystem is not None:
        return component.ecosystem
    return _PURL_ECOSYSTEMS.get((component.purl_type or "").lower())


def _component_name(component: Component, ecosystem: Ecosystem) -> str:
    if ecosystem is Ecosystem.NODE and component.group:
        group = component.group if component.group.startswith("@") else f"@{component.group}"
        return normalize_package_name(f"{group}/{component.name}")
    return normalize_package_name(component.name)


def _depths(sbom: Sbom) -> dict[str, int]:
    """Shortest distance from the SBOM root (BFS over edges); direct deps are depth 1."""
    if sbom.root_ref is None:
        return {}
    children: dict[str, list[str]] = {}
    for edge in sbom.edges:
        children.setdefault(edge.source, []).append(edge.target)
    depth = {sbom.root_ref: 0}
    queue = deque([sbom.root_ref])
    while queue:
        node = queue.popleft()
        for child in children.get(node, ()):
            if child not in depth:
                depth[child] = depth[node] + 1
                queue.append(child)
    return depth


@dataclass
class PackageIndex:
    """Normalized package names known from manifests and the SBOM, per ecosystem."""

    declared: dict[Ecosystem, set[str]] = field(default_factory=dict)
    refs: dict[tuple[Ecosystem, str], str] = field(default_factory=dict)

    @classmethod
    def build(
        cls, sbom: Sbom | None, declared: Mapping[Ecosystem, Collection[str]]
    ) -> "PackageIndex":
        names = {eco: {normalize_package_name(n) for n in deps} for eco, deps in declared.items()}
        index = cls(declared=names)
        if sbom is None:
            return index
        depths = _depths(sbom)
        best: dict[tuple[Ecosystem, str], tuple[int, int, str]] = {}
        for component in sbom.components:
            ecosystem = _component_ecosystem(component)
            if ecosystem is None:
                continue
            key = (ecosystem, _component_name(component, ecosystem))
            rank = (
                0 if component.direct else 1,
                depths.get(component.ref, _UNKNOWN_DEPTH),
                component.ref,
            )
            if key not in best or rank < best[key]:
                best[key] = rank
        index.refs = {key: rank[2] for key, rank in best.items()}
        return index

    def known(self, ecosystem: Ecosystem, name: str) -> bool:
        normalized = normalize_package_name(name)
        return (
            normalized in self.declared.get(ecosystem, ()) or (ecosystem, normalized) in self.refs
        )

    def ref(self, ecosystem: Ecosystem, name: str) -> str | None:
        return self.refs.get((ecosystem, normalize_package_name(name)))

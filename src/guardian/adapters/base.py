"""Adapter contract shared by all ecosystem adapters."""

import re
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import ClassVar

from guardian.core.exceptions import ManifestReadError
from guardian.core.models import (
    Ecosystem,
    EcosystemProfile,
    Framework,
    ManifestFile,
    ManifestKind,
)


@dataclass(frozen=True)
class RepositoryView:
    """Read-only view of a repository's file listing, shared by all adapters.

    ``files`` holds repository-relative paths discovered by the profiler, so adapters never
    walk the filesystem themselves and automatically honour exclusions and symlink policy.
    """

    root: Path
    files: tuple[PurePosixPath, ...]
    max_read_bytes: int

    def named(self, *names: str, case_insensitive: bool = False) -> list[PurePosixPath]:
        if case_insensitive:
            wanted = {n.lower() for n in names}
            return [f for f in self.files if f.name.lower() in wanted]
        wanted = set(names)
        return [f for f in self.files if f.name in wanted]

    def matching(self, predicate: Callable[[PurePosixPath], bool]) -> list[PurePosixPath]:
        return [f for f in self.files if predicate(f)]

    def read_text(self, relative: PurePosixPath) -> str:
        path = self.root / relative
        try:
            size = path.stat().st_size
        except OSError as exc:
            msg = f"Cannot stat {relative}: {exc}"
            raise ManifestReadError(msg) from exc
        if size > self.max_read_bytes:
            msg = f"{relative} is {size} bytes, above the {self.max_read_bytes} byte limit"
            raise ManifestReadError(msg)
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            msg = f"Cannot read {relative}: {exc}"
            raise ManifestReadError(msg) from exc


class EcosystemAdapter(ABC):
    name: ClassVar[str]
    ecosystem: ClassVar[Ecosystem]

    @abstractmethod
    def detect(self, repo: RepositoryView) -> EcosystemProfile | None:
        """Return the ecosystem profile, or ``None`` when the ecosystem is absent."""


_NORMALIZE_RE = re.compile(r"[-_.]+")


def normalize_package_name(name: str) -> str:
    """PEP 503 normalization; also harmless for npm and Maven coordinates."""
    return _NORMALIZE_RE.sub("-", name).lower()


def match_frameworks(dependency_names: Iterable[str], known: dict[str, str]) -> list[str]:
    """Map normalized dependency names onto display names of known frameworks."""
    found = {known[n] for n in (normalize_package_name(d) for d in dependency_names) if n in known}
    return sorted(found)


def sorted_unique(values: Iterable[str]) -> list[str]:
    return sorted(set(values))


def frameworks_from(
    names: Iterable[str],
    known: dict[str, str],
    ecosystem: Ecosystem,
    evidence: PurePosixPath,
) -> list[Framework]:
    return [
        Framework(name=fw, ecosystem=ecosystem, evidence=str(evidence))
        for fw in match_frameworks(names, known)
    ]


def dedupe_frameworks(frameworks: Iterable[Framework]) -> list[Framework]:
    """Keep the first evidence location (by path order) per framework name."""
    seen: dict[str, Framework] = {}
    for fw in sorted(frameworks, key=lambda f: (f.name, f.evidence)):
        seen.setdefault(fw.name, fw)
    return list(seen.values())


def manifest(
    path: PurePosixPath, ecosystem: Ecosystem, kind: ManifestKind, manager: str | None = None
) -> ManifestFile:
    return ManifestFile(path=str(path), ecosystem=ecosystem, kind=kind, package_manager=manager)

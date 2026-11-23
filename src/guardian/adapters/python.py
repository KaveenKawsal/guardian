"""Python ecosystem: pyproject.toml, requirements files, Poetry, uv, Pipenv, PDM."""

import re
import tomllib
from pathlib import PurePosixPath
from typing import Any

from guardian.adapters.base import (
    EcosystemAdapter,
    RepositoryView,
    dedupe_frameworks,
    frameworks_from,
    manifest,
    normalize_package_name,
    sorted_unique,
)
from guardian.core.exceptions import ManifestReadError
from guardian.core.models import Ecosystem, EcosystemProfile, Framework, ManifestFile, ManifestKind

LOCKFILES: dict[str, str] = {
    "poetry.lock": "poetry",
    "uv.lock": "uv",
    "Pipfile.lock": "pipenv",
    "pdm.lock": "pdm",
}

KNOWN_FRAMEWORKS: dict[str, str] = {
    "django": "Django",
    "flask": "Flask",
    "fastapi": "FastAPI",
    "starlette": "Starlette",
    "tornado": "Tornado",
    "aiohttp": "aiohttp",
    "pyramid": "Pyramid",
    "sanic": "Sanic",
    "litestar": "Litestar",
    "celery": "Celery",
    "sqlalchemy": "SQLAlchemy",
    "langchain": "LangChain",
    "langgraph": "LangGraph",
}

# A requirement (requirements.txt line or PEP 508 string) starts with a distribution name.
_REQUIREMENT_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _is_requirements_file(path: PurePosixPath) -> bool:
    name = path.name.lower()
    return name.endswith(".txt") and (
        name.startswith("requirements") or path.parent.name.lower() == "requirements"
    )


def _names_from_pep508(specs: object) -> list[str]:
    if not isinstance(specs, list):
        return []
    return [m.group(1) for s in specs if isinstance(s, str) and (m := _REQUIREMENT_NAME.match(s))]


def _table(data: object, key: str) -> dict[str, Any]:
    value = data.get(key) if isinstance(data, dict) else None
    return value if isinstance(value, dict) else {}


def _pyproject_dependencies(data: dict[str, Any]) -> tuple[list[str], bool]:
    """Return (dependency names, uses_poetry). Tolerates malformed sections."""
    project = _table(data, "project")
    names = _names_from_pep508(project.get("dependencies"))
    for extra in _table(project, "optional-dependencies").values():
        names += _names_from_pep508(extra)
    for group in _table(data, "dependency-groups").values():
        names += _names_from_pep508(group)

    poetry = _table(_table(data, "tool"), "poetry")
    names += [n for n in _table(poetry, "dependencies") if n.lower() != "python"]
    for group in _table(poetry, "group").values():
        names += list(_table(group, "dependencies"))
    return names, bool(poetry)


def _requirements_dependencies(text: str) -> list[str]:
    names = []
    for line in text.splitlines():
        stripped = line.split("#", 1)[0].strip()
        if stripped and not stripped.startswith("-") and (m := _REQUIREMENT_NAME.match(stripped)):
            names.append(m.group(1))
    return names


class PythonAdapter(EcosystemAdapter):
    name = "python"
    ecosystem = Ecosystem.PYTHON

    def detect(self, repo: RepositoryView) -> EcosystemProfile | None:
        manifests: list[ManifestFile] = []
        managers: list[str] = []
        frameworks: list[Framework] = []
        declared: list[str] = []
        warnings: list[str] = []
        eco = self.ecosystem

        for path in repo.named("pyproject.toml"):
            manager = "pip"
            try:
                data = tomllib.loads(repo.read_text(path))
            except (ManifestReadError, tomllib.TOMLDecodeError) as exc:
                warnings.append(f"Could not parse {path}: {exc}")
            else:
                names, uses_poetry = _pyproject_dependencies(data)
                manager = "poetry" if uses_poetry else manager
                frameworks += frameworks_from(names, KNOWN_FRAMEWORKS, eco, path)
                declared += names
            managers.append(manager)
            manifests.append(manifest(path, eco, ManifestKind.MANIFEST, manager))

        for path in repo.matching(_is_requirements_file):
            managers.append("pip")
            manifests.append(manifest(path, eco, ManifestKind.MANIFEST, "pip"))
            try:
                names = _requirements_dependencies(repo.read_text(path))
            except ManifestReadError as exc:
                warnings.append(str(exc))
            else:
                frameworks += frameworks_from(names, KNOWN_FRAMEWORKS, eco, path)
                declared += names

        for path in repo.named("setup.py", "setup.cfg"):
            managers.append("setuptools")
            manifests.append(manifest(path, eco, ManifestKind.MANIFEST, "setuptools"))

        for path in repo.named("Pipfile"):
            managers.append("pipenv")
            manifests.append(manifest(path, eco, ManifestKind.MANIFEST, "pipenv"))

        for path in repo.named(*LOCKFILES):
            managers.append(LOCKFILES[path.name])
            manifests.append(manifest(path, eco, ManifestKind.LOCKFILE, LOCKFILES[path.name]))

        if not manifests:
            return None
        return EcosystemProfile(
            ecosystem=eco,
            adapter=self.name,
            package_managers=sorted_unique(managers),
            manifests=sorted(manifests, key=lambda m: m.path),
            frameworks=dedupe_frameworks(frameworks),
            declared_dependencies=sorted_unique(map(normalize_package_name, declared)),
            warnings=warnings,
        )

"""Node.js ecosystem: package.json plus npm, Yarn, pnpm and Bun lockfiles."""

import json
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
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "yarn.lock": "yarn",
    "pnpm-lock.yaml": "pnpm",
    "bun.lock": "bun",
    "bun.lockb": "bun",
}

KNOWN_FRAMEWORKS: dict[str, str] = {
    "express": "Express",
    "koa": "Koa",
    "fastify": "Fastify",
    "@hapi/hapi": "hapi",
    "@nestjs/core": "NestJS",
    "next": "Next.js",
    "nuxt": "Nuxt",
    "react": "React",
    "vue": "Vue",
    "@angular/core": "Angular",
    "svelte": "Svelte",
    "@sveltejs/kit": "SvelteKit",
    "electron": "Electron",
    "typescript": "TypeScript",
}

DEPENDENCY_SECTIONS = (
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
)


def _dependency_names(data: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for section in DEPENDENCY_SECTIONS:
        deps = data.get(section)
        if isinstance(deps, dict):
            names += list(deps)
    return names


def _declared_manager(data: dict[str, Any]) -> str | None:
    """Corepack's ``"packageManager": "pnpm@9.1.0"`` field."""
    value = data.get("packageManager")
    if isinstance(value, str) and value:
        return value.split("@", 1)[0] or None
    return None


class NodeAdapter(EcosystemAdapter):
    name = "node"
    ecosystem = Ecosystem.NODE

    def detect(self, repo: RepositoryView) -> EcosystemProfile | None:
        manifests: list[ManifestFile] = []
        managers: list[str] = []
        frameworks: list[Framework] = []
        declared: list[str] = []
        warnings: list[str] = []
        eco = self.ecosystem

        lock_dirs: dict[PurePosixPath, str] = {}
        for path in repo.named(*LOCKFILES):
            lock_dirs[path.parent] = LOCKFILES[path.name]
            managers.append(LOCKFILES[path.name])
            manifests.append(manifest(path, eco, ManifestKind.LOCKFILE, LOCKFILES[path.name]))

        for path in repo.named("package.json"):
            manager = lock_dirs.get(path.parent)
            try:
                data = json.loads(repo.read_text(path))
            except (ManifestReadError, json.JSONDecodeError) as exc:
                warnings.append(f"Could not parse {path}: {exc}")
            else:
                if isinstance(data, dict):
                    manager = _declared_manager(data) or manager
                    names = _dependency_names(data)
                    frameworks += frameworks_from(names, KNOWN_FRAMEWORKS, eco, path)
                    declared += names
                else:
                    warnings.append(f"{path} is not a JSON object")
            manager = manager or "npm"
            managers.append(manager)
            manifests.append(manifest(path, eco, ManifestKind.MANIFEST, manager))

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

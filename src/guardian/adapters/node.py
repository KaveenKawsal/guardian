"""Node.js ecosystem: package.json plus npm, Yarn, pnpm and Bun lockfiles."""

import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

from packageurl import PackageURL

from guardian.adapters.base import (
    EcosystemAdapter,
    RepositoryView,
    dedupe_frameworks,
    frameworks_from,
    manifest,
    normalize_package_name,
    sorted_unique,
)
from guardian.core.exceptions import ApplyError, ManifestReadError
from guardian.core.models import Ecosystem, EcosystemProfile, Framework, ManifestFile, ManifestKind
from guardian.core.remediation_models import RemediationActionType, RemediationCandidate
from guardian.remediation.npm_semver import rewrite_spec

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

    def apply_candidate(self, worktree: Path, candidate: RemediationCandidate) -> list[str]:
        return apply_candidate(worktree, candidate)


# --- Remediation: format-preserving package.json edits ----------------------------------

_INDENT_RE = re.compile(r"^\{\s*?\n([ \t]+)\S", re.MULTILINE)
MAX_MANIFEST_EDIT_BYTES = 5 * 1024 * 1024


def _safe_manifest(worktree: Path, relative: str) -> Path:
    """The manifest path inside ``worktree``; refuses escapes and symlinks anywhere on the way."""
    rel = PurePosixPath(relative)
    if rel.is_absolute() or ".." in rel.parts or not rel.parts or rel.name != "package.json":
        msg = f"Refusing manifest path {relative!r}: must be a package.json inside the worktree"
        raise ApplyError(msg)
    root = worktree.resolve()
    current = root
    for part in rel.parts:
        current /= part
        if current.is_symlink():
            msg = f"Refusing to edit {relative}: {current.relative_to(root)} is a symlink"
            raise ApplyError(msg)
    if not current.resolve().is_relative_to(root):
        msg = f"Refusing manifest path {relative!r}: it escapes the worktree"
        raise ApplyError(msg)
    if not current.is_file():
        msg = f"Manifest {relative} does not exist in the worktree"
        raise ApplyError(msg)
    return current


def _detect_format(text: str) -> tuple[str | int, str, bool]:
    """(indent, newline, trailing newline) of a JSON document."""
    newline = "\r\n" if "\r\n" in text else "\n"
    normalized = text.replace("\r\n", "\n")
    match = _INDENT_RE.search(normalized)
    indent: str | int = match.group(1) if match else 2
    if isinstance(indent, str) and set(indent) == {" "}:
        indent = len(indent)
    return indent, newline, normalized.endswith("\n")


def npm_name(purl: str) -> str | None:
    """Package name of an npm purl (``@scope/name`` for scoped packages), else None."""
    try:
        parsed = PackageURL.from_string(purl)
    except ValueError:
        return None
    if parsed.type != "npm":
        return None
    return f"{parsed.namespace}/{parsed.name}" if parsed.namespace else parsed.name


def _section_of(data: dict[str, Any], name: str) -> str | None:
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = data.get(section)
        if isinstance(deps, dict) and isinstance(deps.get(name), str):
            return section
    return None


def _edit(data: dict[str, Any], candidate: RemediationCandidate, relative: str) -> None:
    action = candidate.action_type
    if action in {RemediationActionType.BLOCK, RemediationActionType.ESCALATE}:
        msg = f"{action.value} is a non-code action; there is nothing to apply"
        raise ApplyError(msg)
    name = npm_name(candidate.component)
    if name is None:
        msg = f"{candidate.component} is not an npm package"
        raise ApplyError(msg)
    if candidate.strategy == "override":
        if not candidate.to_version:
            msg = "An override candidate needs a target version"
            raise ApplyError(msg)
        overrides = data.setdefault("overrides", {})
        if not isinstance(overrides, dict):
            msg = f'"overrides" in {relative} is not an object'
            raise ApplyError(msg)
        overrides[name] = candidate.to_version
        return
    target = candidate.target_package if candidate.strategy == "parent" else name
    if not target:
        msg = "A parent-strategy candidate needs target_package"
        raise ApplyError(msg)
    section = _section_of(data, target)
    if section is None:
        msg = f"{target} is not declared in {relative}"
        raise ApplyError(msg)
    if action is RemediationActionType.REMOVE:
        del data[section][target]
        return
    if action not in {RemediationActionType.UPGRADE, RemediationActionType.PIN}:
        msg = f"{action.value} is not supported for npm manifests"
        raise ApplyError(msg)
    if not candidate.to_version:
        msg = f"{action.value} needs a target version"
        raise ApplyError(msg)
    data[section][target] = rewrite_spec(data[section][target], candidate.to_version)


def apply_candidate(worktree: Path, candidate: RemediationCandidate) -> list[str]:
    """Edit package.json in ``worktree`` for ``candidate``; return the changed relative paths.

    Key order, indentation, line endings and the trailing newline are preserved. Lockfiles are
    not touched: the sandbox regenerates them. Raises :class:`ApplyError` for BLOCK/ESCALATE,
    a manifest outside the worktree or behind a symlink, or an undeclared dependency.
    """
    relative = candidate.manifest_path or "package.json"
    path = _safe_manifest(worktree, relative)
    if path.stat().st_size > MAX_MANIFEST_EDIT_BYTES:
        msg = f"{relative} is too large to edit"
        raise ApplyError(msg)
    raw = path.read_bytes()
    text = raw.decode("utf-8-sig")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        msg = f"{relative} is not valid JSON: {exc}"
        raise ApplyError(msg) from exc
    if not isinstance(data, dict):
        msg = f"{relative} is not a JSON object"
        raise ApplyError(msg)
    _edit(data, candidate, relative)
    indent, newline, trailing = _detect_format(text)
    out = json.dumps(data, indent=indent, ensure_ascii=False)
    if trailing:
        out += "\n"
    out = out.replace("\n", newline)
    bom = "﻿" if raw.startswith(b"\xef\xbb\xbf") else ""
    new_bytes = (bom + out).encode("utf-8")
    if new_bytes == raw:
        return []
    path.write_bytes(new_bytes)
    return [str(PurePosixPath(relative))]

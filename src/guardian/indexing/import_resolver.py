"""Resolve raw imports to repository files, third-party packages or the stdlib."""

from collections.abc import Collection, Mapping, Sequence

from guardian.core.models import (
    Ecosystem,
    FileIndex,
    ImportRef,
    ResolvedImport,
    Sbom,
    SourceLanguage,
)
from guardian.indexing._resolution_js import JsResolver
from guardian.indexing._resolution_layout import (
    PackageIndex,
    RepoLayout,
    Resolution,
    clean_path,
)
from guardian.indexing._resolution_python import PythonResolver


def resolve_imports(
    files: Sequence[FileIndex],
    *,
    repo_files: Collection[str],
    sbom: Sbom | None,
    declared: Mapping[Ecosystem, set[str]],
) -> list[ResolvedImport]:
    """One ResolvedImport per ImportRef in ``files``, in input order.

    ``repo_files`` is every repository-relative POSIX path in the repo (not only indexed
    ones). ``declared`` holds normalized dependency names from manifests per ecosystem
    (``RepositoryProfile.declared_dependencies``). Pure: no filesystem access.
    """
    layout = RepoLayout.build([*repo_files, *(f.path for f in files)])
    packages = PackageIndex.build(sbom, declared)
    python = PythonResolver(layout, packages)
    javascript = JsResolver(layout, packages)
    resolved: list[ResolvedImport] = []
    for file_index in files:
        resolver = python if file_index.language is SourceLanguage.PYTHON else javascript
        importer = clean_path(file_index.path)
        resolved.extend(
            _to_model(ref, resolver.resolve(ref, importer)) for ref in file_index.imports
        )
    return resolved


def _to_model(ref: ImportRef, resolution: Resolution) -> ResolvedImport:
    return ResolvedImport(
        path=ref.path,
        line=ref.line,
        module=ref.module,
        style=ref.style,
        target=resolution.target,
        target_path=resolution.target_path,
        package=resolution.package,
        component_ref=resolution.component_ref,
    )

"""Repository indexer: discovers source files and builds the CodeIndex.

The repository is untrusted: files are read only through ``read_source`` (no symlinks, no
junctions, must stay inside the root, bounded size), nothing is imported or executed, and
only the extracted index is kept, never file contents.
"""

import hashlib
import os
import re
import stat
from collections import Counter
from pathlib import Path, PurePosixPath

from guardian.core.config import GuardianSettings
from guardian.core.models import CodeIndex, FileIndex, RepositoryProfile, Sbom, SourceLanguage
from guardian.core.profiler import walk_repository
from guardian.indexing import (
    call_graph,
    entry_points,
    import_resolver,
    symbol_extractor,
    tree_sitter,
)
from guardian.indexing.incremental import IndexCache

MAX_MANIFEST_BYTES = 1024 * 1024
MINIFIED_SUFFIXES = (".min.js", ".min.mjs", "-min.js", ".bundle.js")
MINIFIED_SAMPLE_BYTES = 4096
MINIFIED_AVG_LINE = 300
MAX_NAMED_ERRORS = 5
ENTRY_MANIFESTS = frozenset({"package.json", "pyproject.toml"})

_MAIN_GUARD = re.compile(
    r"""^\s*if\s+(?:__name__\s*==\s*['"]__main__['"]|['"]__main__['"]\s*==\s*__name__)\s*:""",
    re.MULTILINE,
)

# Skip reasons reported in CodeIndex.skipped_files.
TOO_LARGE = "too-large"
MINIFIED = "minified"
UNREADABLE = "unreadable"
LIMIT = "limit"
EXTRACT_ERROR = "extract-error"


class RepositoryIndexer:
    def __init__(self, settings: GuardianSettings, cache: IndexCache | None = None) -> None:
        self.settings = settings
        self.cache = cache

    def index(self, profile: RepositoryProfile, sbom: Sbom | None) -> CodeIndex:
        """Index the repository at ``profile.root``. Never raises for bad files: counts them
        in ``skipped_files`` / ``warnings`` instead."""
        if not self.settings.index_source:
            return CodeIndex(warnings=["Source indexing disabled (index_source=false)"])
        root = Path(profile.root)
        walk = walk_repository(root, self.settings.excluded_dirs, self.settings.max_files)
        repo_files = [p.as_posix() for p in walk.files]
        run = _IndexRun(self, root)
        run.index_files(repo_files)
        warnings = run.warnings
        if walk.truncated:
            warnings.insert(0, f"File walk stopped at max_files={self.settings.max_files}")

        files = sorted(run.files, key=lambda f: f.path)
        imports, calls = [], []
        try:
            imports = import_resolver.resolve_imports(
                files, repo_files=repo_files, sbom=sbom, declared=profile.declared_dependencies
            )
            calls = call_graph.resolve_calls(files, imports)
        except Exception as exc:  # noqa: BLE001 - partial results beat a failed scan
            imports, calls = [], []
            warnings.append(f"Import/call resolution failed, results are partial: {exc!r}")

        manifests = _read_manifests(root, profile.manifest_paths)
        entries = entry_points.detect_entry_points(
            files, calls, main_guard_paths=run.main_guard_paths, manifests=manifests
        )
        return CodeIndex(
            files=files,
            imports=imports,
            calls=calls,
            entry_points=entries,
            skipped_files=dict(sorted(run.skipped.items())),
            warnings=warnings,
        )


class _IndexRun:
    """State of one ``RepositoryIndexer.index`` call."""

    def __init__(self, indexer: RepositoryIndexer, root: Path) -> None:
        self.settings = indexer.settings
        self.cache = indexer.cache
        self.reader = _SafeReader(root)
        self.files: list[FileIndex] = []
        self.main_guard_paths: set[str] = set()
        self.skipped: Counter[str] = Counter()
        self.extract_errors: list[str] = []
        self.warnings: list[str] = []

    def index_files(self, repo_files: list[str]) -> None:
        candidates = sorted(
            (path, language)
            for path in repo_files
            if (language := tree_sitter.language_for(path)) is not None
        )
        for path, language in candidates:
            if len(self.files) >= self.settings.max_indexed_files:
                self.skipped[LIMIT] += 1
                continue
            self._index_one(path, language)
        self._flush_cache()
        if self.skipped[LIMIT]:
            self.warnings.append(
                f"Indexed only the first {self.settings.max_indexed_files} source files; "
                f"{self.skipped[LIMIT]} skipped (max_indexed_files)"
            )
        if self.extract_errors:
            named = ", ".join(self.extract_errors[:MAX_NAMED_ERRORS])
            more = len(self.extract_errors) - MAX_NAMED_ERRORS
            suffix = f" and {more} more" if more > 0 else ""
            self.warnings.append(f"Symbol extraction failed for {named}{suffix}")

    def _index_one(self, path: str, language: SourceLanguage) -> None:
        if PurePosixPath(path).name.lower().endswith(MINIFIED_SUFFIXES):
            self.skipped[MINIFIED] += 1
            return
        data = self.reader.read(path, self.settings.max_source_bytes)
        if isinstance(data, str):
            self.skipped[data] += 1
            return
        if looks_minified(data):
            self.skipped[MINIFIED] += 1
            return
        sha = hashlib.sha256(data).hexdigest()
        file_index = self.cache.get(path, sha, language) if self.cache is not None else None
        if file_index is None:
            try:
                file_index = symbol_extractor.extract_file(path, data, language)
            except Exception:  # noqa: BLE001 - one bad file must not stop the scan
                self.skipped[EXTRACT_ERROR] += 1
                self.extract_errors.append(path)
                return
            if file_index.sha256 != sha or file_index.path != path:
                file_index = file_index.model_copy(update={"sha256": sha, "path": path})
            if self.cache is not None:
                self.cache.put(file_index)
        if language is SourceLanguage.PYTHON and has_main_guard(data):
            self.main_guard_paths.add(path)
        self.files.append(file_index)

    def _flush_cache(self) -> None:
        flush = getattr(self.cache, "flush", None)
        if not callable(flush):
            return
        try:
            flush()
        except Exception as exc:  # noqa: BLE001 - the cache is an optimization
            self.warnings.append(f"Could not save the index cache: {exc!r}")


def has_main_guard(data: bytes) -> bool:
    return _MAIN_GUARD.search(data.decode("utf-8", errors="replace")) is not None


def looks_minified(data: bytes) -> bool:
    """Average line length of the first 4 KB above 300 characters."""
    sample = data[:MINIFIED_SAMPLE_BYTES]
    if not sample:
        return False
    lines = sample.count(b"\n") + 1
    return len(sample) / lines > MINIFIED_AVG_LINE


def _read_manifests(root: Path, manifest_paths: set[str]) -> dict[str, bytes]:
    candidates = {p for p in manifest_paths if PurePosixPath(p).name in ENTRY_MANIFESTS}
    candidates |= ENTRY_MANIFESTS
    reader = _SafeReader(root)
    manifests: dict[str, bytes] = {}
    for path in sorted(candidates):
        data = reader.read(path, MAX_MANIFEST_BYTES)
        if isinstance(data, bytes):
            manifests[path] = data
    return manifests


def read_source(root: Path, relative: str, max_bytes: int) -> bytes | None:
    """Read a repository file safely: must resolve inside ``root``, must not be a symlink,
    must be at most ``max_bytes``. Returns None otherwise."""
    data = _SafeReader(root).read(relative, max_bytes)
    return data if isinstance(data, bytes) else None


def _is_link(path: Path) -> bool:
    isjunction = getattr(os.path, "isjunction", None)  # Python 3.12+
    return path.is_symlink() or bool(isjunction and isjunction(path))


class _SafeReader:
    """Bounded, symlink-refusing reads below one root. Caches verified parent directories
    so indexing thousands of files does not re-check the same parents."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self._safe_dirs: set[PurePosixPath] = {PurePosixPath()}

    def read(self, relative: str, max_bytes: int) -> bytes | str:
        """The file's bytes, or a skip reason (``too-large`` / ``unreadable``)."""
        try:
            target = self._checked_path(relative)
            if target is None:
                return UNREADABLE
            info = target.lstat()
            if not stat.S_ISREG(info.st_mode):
                return UNREADABLE
            if info.st_size > max_bytes:
                return TOO_LARGE
            return self._bounded_read(target, max_bytes)
        except (OSError, ValueError):
            return UNREADABLE

    def _checked_path(self, relative: str) -> Path | None:
        rel = PurePosixPath(relative)
        if rel.is_absolute() or not rel.parts or any(p in {"..", "."} for p in rel.parts):
            return None
        for depth in range(1, len(rel.parts)):
            parent = PurePosixPath(*rel.parts[:depth])
            if parent in self._safe_dirs:
                continue
            if _is_link(self.root.joinpath(*parent.parts)):
                return None
            self._safe_dirs.add(parent)
        target = self.root.joinpath(*rel.parts)
        if _is_link(target) or not target.resolve().is_relative_to(self.root):
            return None
        return target

    @staticmethod
    def _bounded_read(target: Path, max_bytes: int) -> bytes | str:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        fd = os.open(target, flags)
        with os.fdopen(fd, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                return UNREADABLE
            data = handle.read(max_bytes + 1)
        return TOO_LARGE if len(data) > max_bytes else data

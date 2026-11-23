"""Cache of per-file extraction results so unchanged files are not re-parsed across scans.

Entries are keyed by (path, sha256, language, ``tree_sitter.EXTRACTOR_VERSION``): editing a
file changes its hash, and bumping the extractor version invalidates every older entry.
The SQLite-backed implementation lives in ``guardian.storage.code_index``.
"""

from typing import Protocol

from guardian.core.models import FileIndex, SourceLanguage
from guardian.indexing import tree_sitter

CacheKey = tuple[str, str, SourceLanguage, str]


class IndexCache(Protocol):
    """Keyed by (path, sha256, language, EXTRACTOR_VERSION).

    Implementations may buffer ``put`` and expose an optional ``flush()``; the indexer
    calls it once at the end of a run.
    """

    def get(self, path: str, sha256: str, language: SourceLanguage) -> FileIndex | None: ...

    def put(self, file_index: FileIndex) -> None: ...


def cache_key(path: str, sha256: str, language: SourceLanguage) -> CacheKey:
    # Read through the module so a version bump (or a test patch) takes effect immediately.
    return (path, sha256, SourceLanguage(language), tree_sitter.EXTRACTOR_VERSION)


class MemoryIndexCache:
    """In-process cache, e.g. for repeated indexing within one run and for tests."""

    def __init__(self) -> None:
        self._entries: dict[CacheKey, FileIndex] = {}

    def get(self, path: str, sha256: str, language: SourceLanguage) -> FileIndex | None:
        return self._entries.get(cache_key(path, sha256, language))

    def put(self, file_index: FileIndex) -> None:
        key = cache_key(file_index.path, file_index.sha256, file_index.language)
        self._entries[key] = file_index

    def __len__(self) -> int:
        return len(self._entries)

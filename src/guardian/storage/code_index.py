"""Codebase index per scan, and the cross-scan per-file extraction cache."""

import zlib
from typing import TYPE_CHECKING

from pydantic import ValidationError

from guardian.core.models import CodeIndex, FileIndex, SourceLanguage
from guardian.indexing.incremental import CacheKey, cache_key

if TYPE_CHECKING:
    from guardian.storage.database import Database


class CodeIndexStore:
    def __init__(self, db: "Database") -> None:
        self.db = db

    def save(self, scan_id: str, index: CodeIndex) -> None:
        blob = zlib.compress(index.model_dump_json().encode("utf-8"))
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO code_indexes (scan_id, file_count, symbol_count, "
                "import_count, call_count, index_blob) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    scan_id,
                    len(index.files),
                    sum(len(f.symbols) for f in index.files),
                    len(index.imports),
                    len(index.calls),
                    blob,
                ),
            )

    def load(self, scan_id: str) -> CodeIndex | None:
        row = self.db.conn.execute(
            "SELECT index_blob FROM code_indexes WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        if row is None:
            return None
        return CodeIndex.model_validate_json(zlib.decompress(row["index_blob"]))

    def cache(self) -> "SqliteIndexCache":
        return SqliteIndexCache(self.db)


class SqliteIndexCache:
    """``IndexCache`` backed by ``file_index_cache``. ``put`` is buffered; ``flush`` writes
    all pending entries in one transaction."""

    def __init__(self, db: "Database") -> None:
        self.db = db
        self._pending: dict[CacheKey, FileIndex] = {}

    def get(self, path: str, sha256: str, language: SourceLanguage) -> FileIndex | None:
        key = cache_key(path, sha256, language)
        if pending := self._pending.get(key):
            return pending
        row = self.db.conn.execute(
            "SELECT index_blob FROM file_index_cache WHERE path = ? AND sha256 = ? "
            "AND language = ? AND extractor_version = ?",
            (key[0], key[1], key[2].value, key[3]),
        ).fetchone()
        if row is None:
            return None
        try:
            cached = FileIndex.model_validate_json(zlib.decompress(row["index_blob"]))
        except (zlib.error, ValidationError):
            return None  # corrupt entry: re-extract, flush will overwrite it
        return cached if (cached.path, cached.sha256) == (path, sha256) else None

    def put(self, file_index: FileIndex) -> None:
        key = cache_key(file_index.path, file_index.sha256, file_index.language)
        self._pending[key] = file_index

    def flush(self) -> None:
        if not self._pending:
            return
        rows = [
            (
                path,
                sha256,
                language.value,
                version,
                zlib.compress(fi.model_dump_json().encode("utf-8")),
            )
            for (path, sha256, language, version), fi in self._pending.items()
        ]
        with self.db.transaction() as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO file_index_cache (path, sha256, language, "
                "extractor_version, index_blob) VALUES (?, ?, ?, ?, ?)",
                rows,
            )
        self._pending.clear()

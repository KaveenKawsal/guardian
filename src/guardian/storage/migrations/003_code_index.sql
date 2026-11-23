-- Guardian storage schema, version 3: codebase index (phase 4).

CREATE TABLE code_indexes (
    scan_id       TEXT PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
    file_count    INTEGER NOT NULL DEFAULT 0,
    symbol_count  INTEGER NOT NULL DEFAULT 0,
    import_count  INTEGER NOT NULL DEFAULT 0,
    call_count    INTEGER NOT NULL DEFAULT 0,
    index_blob    BLOB NOT NULL  -- zlib-compressed CodeIndex JSON
);

-- Per-file extraction results reused across scans while the file and extractor are unchanged.
CREATE TABLE file_index_cache (
    path               TEXT NOT NULL,
    sha256             TEXT NOT NULL,
    language           TEXT NOT NULL,
    extractor_version  TEXT NOT NULL,
    index_blob         BLOB NOT NULL,  -- zlib-compressed FileIndex JSON
    PRIMARY KEY (path, sha256, language, extractor_version)
);

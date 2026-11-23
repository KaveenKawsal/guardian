-- Guardian storage schema, version 1: repositories, scans, SBOMs.
-- Timestamps are ISO-8601 UTC strings. JSON columns hold Pydantic-serialized values.

CREATE TABLE repositories (
    id          INTEGER PRIMARY KEY,
    root_path   TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE scans (
    id               TEXT PRIMARY KEY,
    repository_id    INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    status           TEXT NOT NULL,
    started_at       TEXT NOT NULL,
    finished_at      TEXT,
    git_branch       TEXT,
    git_commit       TEXT,
    component_count  INTEGER NOT NULL DEFAULT 0,
    profile_json     TEXT,
    warnings_json    TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX scans_by_repository ON scans(repository_id, started_at);

CREATE TABLE tool_runs (
    id                INTEGER PRIMARY KEY,
    scan_id           TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    tool              TEXT NOT NULL,
    status            TEXT NOT NULL,
    exit_code         INTEGER,
    duration_seconds  REAL NOT NULL DEFAULT 0,
    error             TEXT
);
CREATE INDEX tool_runs_by_scan ON tool_runs(scan_id);

CREATE TABLE sboms (
    scan_id        TEXT PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
    spec_version   TEXT NOT NULL,
    generator      TEXT NOT NULL,
    root_ref       TEXT,
    direct_source  TEXT NOT NULL,
    warnings_json  TEXT NOT NULL DEFAULT '[]',
    raw_bom        BLOB  -- zlib-compressed CycloneDX JSON, kept as evidence
);

CREATE TABLE components (
    scan_id           TEXT NOT NULL REFERENCES sboms(scan_id) ON DELETE CASCADE,
    ref               TEXT NOT NULL,
    name              TEXT NOT NULL,
    grp               TEXT,
    version           TEXT,
    purl              TEXT,
    purl_type         TEXT,
    ecosystem         TEXT,
    component_type    TEXT NOT NULL,
    scope             TEXT NOT NULL,
    direct            INTEGER,  -- NULL when unknown
    licenses_json     TEXT NOT NULL DEFAULT '[]',
    declared_in_json  TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (scan_id, ref)
);
CREATE INDEX components_by_purl ON components(purl);
CREATE INDEX components_by_name ON components(name);

CREATE TABLE dependency_edges (
    scan_id  TEXT NOT NULL REFERENCES sboms(scan_id) ON DELETE CASCADE,
    source   TEXT NOT NULL,
    target   TEXT NOT NULL,
    PRIMARY KEY (scan_id, source, target)
);

-- Guardian storage schema, version 2: security findings and git changes.

ALTER TABLE scans ADD COLUMN finding_count INTEGER NOT NULL DEFAULT 0;

CREATE TABLE findings (
    scan_id        TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    id             TEXT NOT NULL,  -- stable across scans for the same issue
    kind           TEXT NOT NULL,
    severity       TEXT NOT NULL,
    severity_rank  INTEGER NOT NULL,
    title          TEXT NOT NULL,
    tool           TEXT NOT NULL,
    component_ref  TEXT,
    path           TEXT,
    start_line     INTEGER,
    introduced_by  TEXT,
    finding_json   TEXT NOT NULL,  -- full Finding incl. details and evidence
    PRIMARY KEY (scan_id, id)
);
CREATE INDEX findings_by_rank ON findings(scan_id, severity_rank DESC);
CREATE INDEX findings_by_id ON findings(id);

CREATE TABLE changes (
    scan_id      TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    commit_sha   TEXT NOT NULL,
    record_json  TEXT NOT NULL,
    PRIMARY KEY (scan_id, commit_sha)
);

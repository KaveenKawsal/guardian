-- Guardian storage schema, version 6: AI investigator runs (Milestone 8).
--
-- One row per `guardian investigate` run over a scan. provider_calls_json records every LLM
-- call (provider, model, latency, tokens, status); trace_json holds the graph's node
-- started/finished events so the UI can draw which parts of the architecture ran.

CREATE TABLE investigation_runs (
    id                   TEXT PRIMARY KEY,
    scan_id              TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    started_at           TEXT NOT NULL,
    finished_at          TEXT,
    status               TEXT NOT NULL,
    provider_calls_json  TEXT NOT NULL DEFAULT '[]',
    trace_json           TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX investigation_runs_by_scan ON investigation_runs(scan_id, started_at);

CREATE TABLE investigation_reports (
    run_id        TEXT NOT NULL REFERENCES investigation_runs(id) ON DELETE CASCADE,
    subject_kind  TEXT NOT NULL CHECK (subject_kind IN ('case', 'finding', 'scan')),
    subject_id    TEXT NOT NULL,
    agent         TEXT NOT NULL,
    report_json   TEXT NOT NULL,
    source        TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    PRIMARY KEY (run_id, subject_kind, subject_id, agent)
);
CREATE INDEX investigation_reports_by_subject ON investigation_reports(subject_id);

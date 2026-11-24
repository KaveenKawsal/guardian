-- Guardian storage schema, version 4: human-approved remediation and the audit log.
-- *_json columns hold the full Pydantic model; the other columns exist for lookups.

CREATE TABLE remediation_cases (
    id               TEXT PRIMARY KEY,           -- rc_<12 hex>
    fingerprint      TEXT NOT NULL UNIQUE,
    scan_id          TEXT NOT NULL REFERENCES scans(id),
    repository_root  TEXT NOT NULL,
    status           TEXT NOT NULL,
    priority         TEXT NOT NULL,
    jira_key         TEXT,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    case_json        TEXT NOT NULL
);
CREATE INDEX remediation_cases_by_status ON remediation_cases(status, updated_at);

CREATE TABLE remediation_candidates (
    id              TEXT PRIMARY KEY,            -- cand_<12 hex>
    case_id         TEXT NOT NULL REFERENCES remediation_cases(id) ON DELETE CASCADE,
    position        INTEGER NOT NULL,
    action_type     TEXT NOT NULL,
    candidate_json  TEXT NOT NULL
);
CREATE INDEX remediation_candidates_by_case ON remediation_candidates(case_id, position);

CREATE TABLE remediation_plans (
    id          INTEGER PRIMARY KEY,
    case_id     TEXT NOT NULL REFERENCES remediation_cases(id) ON DELETE CASCADE,
    created_at  TEXT NOT NULL,
    plan_json   TEXT NOT NULL
);
CREATE INDEX remediation_plans_by_case ON remediation_plans(case_id, id);

CREATE TABLE human_decisions (
    id               INTEGER PRIMARY KEY,
    case_id          TEXT NOT NULL REFERENCES remediation_cases(id) ON DELETE CASCADE,
    decision         TEXT NOT NULL,
    actor_id         TEXT NOT NULL,
    channel          TEXT NOT NULL,
    jira_comment_id  TEXT UNIQUE,                -- re-syncing a comment is a no-op
    decided_at       TEXT NOT NULL,
    decision_json    TEXT NOT NULL
);
CREATE INDEX human_decisions_by_case ON human_decisions(case_id, id);

CREATE TABLE validation_runs (
    id          INTEGER PRIMARY KEY,
    case_id     TEXT NOT NULL REFERENCES remediation_cases(id) ON DELETE CASCADE,
    started_at  TEXT NOT NULL,
    run_json    TEXT NOT NULL
);
CREATE INDEX validation_runs_by_case ON validation_runs(case_id, id);

CREATE TABLE verification_results (
    id           INTEGER PRIMARY KEY,
    case_id      TEXT NOT NULL REFERENCES remediation_cases(id) ON DELETE CASCADE,
    status       TEXT NOT NULL,
    result_json  TEXT NOT NULL
);
CREATE INDEX verification_results_by_case ON verification_results(case_id, id);

CREATE TABLE jira_links (
    case_id                 TEXT PRIMARY KEY REFERENCES remediation_cases(id) ON DELETE CASCADE,
    issue_key               TEXT NOT NULL UNIQUE,
    fingerprint             TEXT NOT NULL,
    last_synced_comment_id  TEXT,
    updated_at              TEXT NOT NULL
);

-- One global hash chain. case_id is deliberately not a foreign key: the log outlives the rows
-- it describes, and a cascading delete must never reach it.
CREATE TABLE audit_events (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id            TEXT,
    event              TEXT NOT NULL,
    actor              TEXT NOT NULL,
    at                 TEXT NOT NULL,
    payload_json       TEXT NOT NULL,
    payload_sha256     TEXT NOT NULL,
    prev_event_sha256  TEXT UNIQUE,              -- a fork in the chain fails loudly
    event_sha256       TEXT NOT NULL UNIQUE
);
CREATE INDEX audit_events_by_case ON audit_events(case_id, id);

CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;

CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;

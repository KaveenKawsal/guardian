-- Guardian storage schema, version 5: small key/value state, e.g. the last Jira sync time.

CREATE TABLE kv_state (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

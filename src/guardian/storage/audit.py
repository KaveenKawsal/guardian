"""Append-only, hash-chained audit log for remediation cases.

There is deliberately no update or delete path here; SQLite triggers reject both as well. Each
event's hash covers the previous event's hash, so ``verify`` detects any row that was changed,
removed or reordered by someone who bypassed the triggers.
"""

import sqlite3
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from pydantic import BaseModel

from guardian.core.remediation_models import (
    AuditEvent,
    audit_event_hash,
    canonical_json,
    sha256_hex,
)

if TYPE_CHECKING:
    from guardian.storage.database import Database

AuditPayload = Mapping[str, object] | BaseModel


def append_event(  # noqa: PLR0913 - one argument per audit field
    conn: sqlite3.Connection,
    case_id: str | None,
    event: str,
    actor: str,
    payload: AuditPayload | None = None,
    *,
    at: datetime | None = None,
) -> AuditEvent:
    """Append inside the caller's open transaction (so a state change and its event commit
    together). Prefer ``AuditStore.append`` unless you already hold a transaction."""
    at_text = (at or datetime.now(UTC)).isoformat()
    payload_json = canonical_json(payload if payload is not None else {})
    payload_sha256 = sha256_hex(payload_json)
    last = conn.execute("SELECT event_sha256 FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
    prev = last[0] if last else None
    event_sha256 = audit_event_hash(prev, case_id, event, actor, at_text, payload_sha256)
    cursor = conn.execute(
        "INSERT INTO audit_events (case_id, event, actor, at, payload_json, payload_sha256, "
        "prev_event_sha256, event_sha256) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (case_id, event, actor, at_text, payload_json, payload_sha256, prev, event_sha256),
    )
    return AuditEvent(
        id=cursor.lastrowid,
        case_id=case_id,
        event=event,
        actor=actor,
        at=datetime.fromisoformat(at_text),
        payload_json=payload_json,
        payload_sha256=payload_sha256,
        prev_event_sha256=prev,
        event_sha256=event_sha256,
    )


def _event(row: sqlite3.Row) -> AuditEvent:
    return AuditEvent(
        id=row["id"],
        case_id=row["case_id"],
        event=row["event"],
        actor=row["actor"],
        at=datetime.fromisoformat(row["at"]),
        payload_json=row["payload_json"],
        payload_sha256=row["payload_sha256"],
        prev_event_sha256=row["prev_event_sha256"],
        event_sha256=row["event_sha256"],
    )


class AuditStore:
    def __init__(self, db: "Database") -> None:
        self.db = db

    def append(
        self,
        case_id: str | None,
        event: str,
        actor: str,
        payload: AuditPayload | None = None,
    ) -> AuditEvent:
        with self.db.transaction() as conn:
            return append_event(conn, case_id, event, actor, payload)

    def verify(self) -> tuple[bool, list[str]]:
        """Recompute every payload hash, event hash and chain link. Returns (ok, problems)."""
        problems: list[str] = []
        prev: str | None = None
        for row in self.db.conn.execute("SELECT * FROM audit_events ORDER BY id"):
            label = f"event {row['id']} ({row['event']})"
            if sha256_hex(row["payload_json"]) != row["payload_sha256"]:
                problems.append(f"{label}: payload does not match payload_sha256")
            if row["prev_event_sha256"] != prev:
                problems.append(f"{label}: chain broken, prev_event_sha256 does not match")
            expected = audit_event_hash(
                row["prev_event_sha256"],
                row["case_id"],
                row["event"],
                row["actor"],
                row["at"],
                row["payload_sha256"],
            )
            if expected != row["event_sha256"]:
                problems.append(f"{label}: event_sha256 does not match its fields")
            prev = row["event_sha256"]
        return not problems, problems

    def list(self, case_id: str | None = None) -> list[AuditEvent]:
        if case_id is None:
            rows = self.db.conn.execute("SELECT * FROM audit_events ORDER BY id")
        else:
            rows = self.db.conn.execute(
                "SELECT * FROM audit_events WHERE case_id = ? ORDER BY id", (case_id,)
            )
        return [_event(r) for r in rows]

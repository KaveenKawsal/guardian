"""Small key/value state that is not worth its own table (e.g. the last Jira sync time)."""

from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from guardian.storage.database import Database


class KvStateStore:
    def __init__(self, db: "Database") -> None:
        self.db = db

    def get(self, key: str) -> str | None:
        row = self.db.conn.execute("SELECT value FROM kv_state WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set(self, key: str, value: str) -> None:
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO kv_state (key, value, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
                "updated_at = excluded.updated_at",
                (key, value, datetime.now(UTC).isoformat()),
            )

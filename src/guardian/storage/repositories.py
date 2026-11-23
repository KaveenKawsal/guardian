"""Repository records."""

from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from guardian.storage.database import Database


class RepositoryStore:
    def __init__(self, db: "Database") -> None:
        self.db = db

    def upsert(self, root_path: str, name: str) -> int:
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO repositories (root_path, name, created_at) VALUES (?, ?, ?) "
                "ON CONFLICT(root_path) DO UPDATE SET name = excluded.name",
                (root_path, name, datetime.now(UTC).isoformat()),
            )
            row = conn.execute(
                "SELECT id FROM repositories WHERE root_path = ?", (root_path,)
            ).fetchone()
        return int(row["id"])

    def find_id(self, root_path: str) -> int | None:
        row = self.db.conn.execute(
            "SELECT id FROM repositories WHERE root_path = ?", (root_path,)
        ).fetchone()
        return int(row["id"]) if row else None

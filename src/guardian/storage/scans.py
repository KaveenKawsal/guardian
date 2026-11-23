"""Scan records and their tool runs."""

import json
import sqlite3
from datetime import datetime
from typing import TYPE_CHECKING

from guardian.core.exceptions import GuardianError
from guardian.core.models import RepositoryProfile, ScanRecord, ScanStatus, ToolRunSummary

if TYPE_CHECKING:
    from guardian.storage.database import Database


class ScanNotFoundError(GuardianError):
    """No scan matches the given identifier."""


_SELECT = """
SELECT s.*, r.name AS repository_name, r.root_path AS repository_root
FROM scans s JOIN repositories r ON r.id = s.repository_id
"""


class ScanStore:
    def __init__(self, db: "Database") -> None:
        self.db = db

    def create(
        self, scan_id: str, repository_id: int, started_at: datetime, profile: RepositoryProfile
    ) -> None:
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO scans (id, repository_id, status, started_at, git_branch, "
                "git_commit, profile_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    scan_id,
                    repository_id,
                    ScanStatus.RUNNING.value,
                    started_at.isoformat(),
                    profile.git.branch,
                    profile.git.head_commit,
                    profile.model_dump_json(),
                ),
            )

    def finish(  # noqa: PLR0913 - one column per argument
        self,
        scan_id: str,
        *,
        status: ScanStatus,
        finished_at: datetime,
        tool_runs: list[ToolRunSummary],
        warnings: list[str],
        component_count: int,
        finding_count: int = 0,
    ) -> None:
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE scans SET status = ?, finished_at = ?, warnings_json = ?, "
                "component_count = ?, finding_count = ? WHERE id = ?",
                (
                    status.value,
                    finished_at.isoformat(),
                    json.dumps(warnings),
                    component_count,
                    finding_count,
                    scan_id,
                ),
            )
            conn.executemany(
                "INSERT INTO tool_runs (scan_id, tool, status, exit_code, duration_seconds, "
                "error) VALUES (?, ?, ?, ?, ?, ?)",
                [
                    (scan_id, t.tool, t.status, t.exit_code, t.duration_seconds, t.error)
                    for t in tool_runs
                ],
            )

    def get(self, scan_id: str) -> ScanRecord:
        row = self.db.conn.execute(f"{_SELECT} WHERE s.id = ?", (scan_id,)).fetchone()
        if row is None:
            msg = f"No scan with id {scan_id!r}"
            raise ScanNotFoundError(msg)
        return self._record(row)

    def resolve(self, identifier: str, repository_root: str | None = None) -> str:
        """Resolve a full id, unique id prefix or ``latest`` to a scan id."""
        if identifier == "latest":
            query = "SELECT s.id FROM scans s JOIN repositories r ON r.id = s.repository_id"
            params: tuple[str, ...] = ()
            if repository_root:
                query += " WHERE r.root_path = ?"
                params = (repository_root,)
            row = self.db.conn.execute(f"{query} ORDER BY s.started_at DESC LIMIT 1", params)
            found = row.fetchone()
            if found is None:
                msg = "No scans recorded yet"
                raise ScanNotFoundError(msg)
            return str(found["id"])

        escaped = identifier.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        rows = self.db.conn.execute(
            "SELECT id FROM scans WHERE id LIKE ? ESCAPE '\\' LIMIT 2", (f"{escaped}%",)
        ).fetchall()
        if not rows:
            msg = f"No scan matches {identifier!r}"
            raise ScanNotFoundError(msg)
        if len(rows) > 1:
            msg = f"Scan id prefix {identifier!r} is ambiguous; use more characters"
            raise ScanNotFoundError(msg)
        return str(rows[0]["id"])

    def recent(self, repository_root: str | None = None, limit: int = 20) -> list[ScanRecord]:
        query, params = _SELECT, ()
        if repository_root:
            query += " WHERE r.root_path = ?"
            params = (repository_root,)
        rows = self.db.conn.execute(
            f"{query} ORDER BY s.started_at DESC LIMIT ?",
            (*params, limit),
        ).fetchall()
        return [self._record(r) for r in rows]

    def profile(self, scan_id: str) -> RepositoryProfile:
        row = self.db.conn.execute(
            "SELECT profile_json FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        if row is None or row["profile_json"] is None:
            msg = f"No profile stored for scan {scan_id!r}"
            raise ScanNotFoundError(msg)
        return RepositoryProfile.model_validate_json(row["profile_json"])

    def _record(self, row: sqlite3.Row) -> ScanRecord:
        runs = self.db.conn.execute(
            "SELECT tool, status, exit_code, duration_seconds, error FROM tool_runs "
            "WHERE scan_id = ? ORDER BY id",
            (row["id"],),
        ).fetchall()
        return ScanRecord(
            id=row["id"],
            repository_name=row["repository_name"],
            repository_root=row["repository_root"],
            status=ScanStatus(row["status"]),
            started_at=datetime.fromisoformat(row["started_at"]),
            finished_at=datetime.fromisoformat(row["finished_at"]) if row["finished_at"] else None,
            git_branch=row["git_branch"],
            git_commit=row["git_commit"],
            component_count=row["component_count"],
            finding_count=row["finding_count"],
            tool_runs=[ToolRunSummary(**dict(r)) for r in runs],
            warnings=json.loads(row["warnings_json"]),
        )

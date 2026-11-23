"""Security findings and git change records per scan."""

from typing import TYPE_CHECKING

from guardian.core.exceptions import GuardianError
from guardian.core.models import ChangeRecord, Finding, FindingKind, Severity

if TYPE_CHECKING:
    from guardian.storage.database import Database


class FindingNotFoundError(GuardianError):
    """No finding matches the given identifier."""


class FindingStore:
    def __init__(self, db: "Database") -> None:
        self.db = db

    def save(self, scan_id: str, findings: list[Finding], changes: list[ChangeRecord]) -> None:
        with self.db.transaction() as conn:
            conn.executemany(
                "INSERT INTO findings (scan_id, id, kind, severity, severity_rank, title, tool, "
                "component_ref, path, start_line, introduced_by, finding_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        scan_id,
                        f.id,
                        f.kind.value,
                        f.severity.value,
                        f.severity.rank,
                        f.title,
                        f.tool,
                        f.component_ref,
                        f.path,
                        f.start_line,
                        f.introduced_by,
                        f.model_dump_json(),
                    )
                    for f in findings
                ],
            )
            conn.executemany(
                "INSERT OR IGNORE INTO changes (scan_id, commit_sha, record_json) VALUES (?, ?, ?)",
                [(scan_id, c.commit, c.model_dump_json()) for c in changes],
            )

    def load(
        self,
        scan_id: str,
        *,
        min_severity: Severity | None = None,
        kind: FindingKind | None = None,
    ) -> list[Finding]:
        query = "SELECT finding_json FROM findings WHERE scan_id = ?"
        params: list[object] = [scan_id]
        if min_severity is not None:
            query += " AND severity_rank >= ?"
            params.append(min_severity.rank)
        if kind is not None:
            query += " AND kind = ?"
            params.append(kind.value)
        query += " ORDER BY severity_rank DESC, kind, title"
        return [
            Finding.model_validate_json(row["finding_json"])
            for row in self.db.conn.execute(query, params)
        ]

    def get(self, scan_id: str, identifier: str) -> Finding:
        """Look up a finding in a scan by full id or unique id prefix."""
        escaped = identifier.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        rows = self.db.conn.execute(
            "SELECT finding_json FROM findings WHERE scan_id = ? AND id LIKE ? ESCAPE '\\' LIMIT 2",
            (scan_id, f"{escaped}%"),
        ).fetchall()
        if not rows:
            msg = f"No finding matches {identifier!r} in scan {scan_id[:12]}"
            raise FindingNotFoundError(msg)
        if len(rows) > 1:
            msg = f"Finding id prefix {identifier!r} is ambiguous; use more characters"
            raise FindingNotFoundError(msg)
        return Finding.model_validate_json(rows[0]["finding_json"])

    def changes(self, scan_id: str) -> list[ChangeRecord]:
        return [
            ChangeRecord.model_validate_json(row["record_json"])
            for row in self.db.conn.execute(
                "SELECT record_json FROM changes WHERE scan_id = ? ORDER BY rowid", (scan_id,)
            )
        ]

    def scans_containing(self, finding_id: str) -> list[str]:
        """Scan ids (newest first) in which this finding was reported: tracks persistence."""
        rows = self.db.conn.execute(
            "SELECT f.scan_id FROM findings f JOIN scans s ON s.id = f.scan_id "
            "WHERE f.id = ? ORDER BY s.started_at DESC",
            (finding_id,),
        )
        return [row["scan_id"] for row in rows]

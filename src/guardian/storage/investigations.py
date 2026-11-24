"""AI investigation runs and their per-subject reports (migration 006).

A run and all of its reports are written in one transaction by the graph's ``persist`` node, so a
reader never sees half a run.
"""

import json
from datetime import datetime
from typing import TYPE_CHECKING, Any

from guardian.investigation.models import (
    CallRecord,
    InvestigationRun,
    InvestigatorReport,
    TraceEvent,
)

if TYPE_CHECKING:
    from guardian.storage.database import Database


class InvestigationStore:
    def __init__(self, db: "Database") -> None:
        self.db = db

    def save_run(self, run: InvestigationRun, reports: list[InvestigatorReport]) -> None:
        trace: dict[str, Any] = {
            "events": [e.model_dump(mode="json") for e in run.trace],
            "notes": run.notes,
            "ai_enabled": run.ai_enabled,
            "max_calls": run.max_calls,
        }
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO investigation_runs (id, scan_id, started_at, finished_at, "
                "status, provider_calls_json, trace_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    run.id,
                    run.scan_id,
                    run.started_at.isoformat(),
                    run.finished_at.isoformat() if run.finished_at else None,
                    run.status,
                    json.dumps([c.model_dump(mode="json") for c in run.provider_calls]),
                    json.dumps(trace),
                ),
            )
            conn.execute("DELETE FROM investigation_reports WHERE run_id = ?", (run.id,))
            conn.executemany(
                "INSERT INTO investigation_reports (run_id, subject_kind, subject_id, agent, "
                "report_json, source, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        run.id,
                        r.subject_kind,
                        r.subject_id,
                        r.agent,
                        r.model_dump_json(),
                        r.source,
                        r.created_at.isoformat(),
                    )
                    for r in reports
                ],
            )

    def _run(self, row: Any) -> InvestigationRun:  # noqa: ANN401 - sqlite3.Row
        trace = json.loads(row["trace_json"] or "{}")
        if isinstance(trace, list):  # tolerate a bare event list
            trace = {"events": trace}
        return InvestigationRun(
            id=row["id"],
            scan_id=row["scan_id"],
            started_at=datetime.fromisoformat(row["started_at"]),
            finished_at=datetime.fromisoformat(row["finished_at"]) if row["finished_at"] else None,
            status=row["status"],
            ai_enabled=bool(trace.get("ai_enabled", True)),
            max_calls=int(trace.get("max_calls", 0)),
            provider_calls=[
                CallRecord.model_validate(c) for c in json.loads(row["provider_calls_json"])
            ],
            trace=[TraceEvent.model_validate(e) for e in trace.get("events", [])],
            notes=list(trace.get("notes", [])),
        )

    def latest_run(self, scan_id: str) -> InvestigationRun | None:
        row = self.db.conn.execute(
            "SELECT * FROM investigation_runs WHERE scan_id = ? "
            "ORDER BY started_at DESC, rowid DESC LIMIT 1",
            (scan_id,),
        ).fetchone()
        return self._run(row) if row else None

    def get_run(self, run_id: str) -> InvestigationRun | None:
        row = self.db.conn.execute(
            "SELECT * FROM investigation_runs WHERE id = ?", (run_id,)
        ).fetchone()
        return self._run(row) if row else None

    def reports(self, run_id: str, subject_id: str | None = None) -> list[InvestigatorReport]:
        query = "SELECT report_json FROM investigation_reports WHERE run_id = ?"
        params: tuple[str, ...] = (run_id,)
        if subject_id is not None:
            query += " AND subject_id = ?"
            params = (run_id, subject_id)
        rows = self.db.conn.execute(query + " ORDER BY rowid", params).fetchall()
        return [InvestigatorReport.model_validate_json(r["report_json"]) for r in rows]

    def count_runs(self) -> int:
        return int(self.db.conn.execute("SELECT COUNT(*) FROM investigation_runs").fetchone()[0])

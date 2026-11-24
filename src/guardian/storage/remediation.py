"""Remediation cases and everything attached to them: candidates, plans, decisions,
validation runs, verification results and Jira links.

Case creation and every status change append an audit event in the same transaction.
"""

import sqlite3
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from guardian.core.exceptions import GuardianError
from guardian.core.remediation_models import (
    CaseStatus,
    HumanDecision,
    JiraLink,
    RemediationCandidate,
    RemediationCase,
    RemediationPlan,
    ValidationRun,
    VerificationResult,
)
from guardian.storage.audit import AuditPayload, append_event

if TYPE_CHECKING:
    from guardian.storage.database import Database

SYSTEM_ACTOR = "guardian"


class RemediationCaseNotFoundError(GuardianError):
    """No remediation case matches the given identifier."""


class RemediationStore:
    def __init__(self, db: "Database") -> None:
        self.db = db

    # --- cases ---------------------------------------------------------------------------

    def create(self, case: RemediationCase, actor: str = SYSTEM_ACTOR) -> RemediationCase:
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO remediation_cases (id, fingerprint, scan_id, repository_root, "
                "status, priority, jira_key, created_at, updated_at, case_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    case.id,
                    case.fingerprint,
                    case.scan_id,
                    case.repository_root,
                    case.status.value,
                    case.priority.value,
                    case.jira_key,
                    case.created_at.isoformat(),
                    case.updated_at.isoformat(),
                    case.model_dump_json(),
                ),
            )
            append_event(conn, case.id, "case:created", actor, case, at=case.created_at)
        return case

    def get(self, case_id: str) -> RemediationCase:
        row = self.db.conn.execute(
            "SELECT case_json FROM remediation_cases WHERE id = ?", (case_id,)
        ).fetchone()
        if row is None:
            msg = f"No remediation case with id {case_id!r}"
            raise RemediationCaseNotFoundError(msg)
        return RemediationCase.model_validate_json(row["case_json"])

    def by_fingerprint(self, fingerprint: str) -> RemediationCase | None:
        row = self.db.conn.execute(
            "SELECT case_json FROM remediation_cases WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        return RemediationCase.model_validate_json(row["case_json"]) if row else None

    def update_status(
        self,
        case_id: str,
        to: CaseStatus,
        *,
        actor: str = SYSTEM_ACTOR,
        payload: AuditPayload | None = None,
    ) -> RemediationCase:
        """Move a case along an allowed edge (``IllegalTransitionError`` otherwise) and audit it."""
        with self.db.transaction() as conn:
            current = self.get(case_id)
            updated = current.transition(to)
            self._write_case(conn, updated)
            append_event(
                conn,
                case_id,
                f"status:{current.status.value}->{to.value}",
                actor,
                payload,
                at=updated.updated_at,
            )
        return updated

    def _write_case(self, conn: sqlite3.Connection, case: RemediationCase) -> None:
        conn.execute(
            "UPDATE remediation_cases SET status = ?, priority = ?, jira_key = ?, "
            "updated_at = ?, case_json = ? WHERE id = ?",
            (
                case.status.value,
                case.priority.value,
                case.jira_key,
                case.updated_at.isoformat(),
                case.model_dump_json(),
                case.id,
            ),
        )

    # --- candidates and plans ------------------------------------------------------------

    def save_candidates(self, case_id: str, candidates: list[RemediationCandidate]) -> None:
        """Upsert by candidate id (IDs are deterministic, so a re-run replaces, not duplicates)."""
        with self.db.transaction() as conn:
            self._upsert_candidates(conn, case_id, candidates)

    def replace_candidates(
        self,
        case_id: str,
        candidates: list[RemediationCandidate],
        *,
        actor: str = SYSTEM_ACTOR,
    ) -> list[str]:
        """Make ``candidates`` the case's complete candidate set; return the removed ids.

        Used when a case is refreshed from a newer scan: candidates the new scan no longer
        produces disappear (a decision naming one then fails loudly at apply time instead of
        acting on stale facts). The removal is audited, so the trail keeps the old ids.
        """
        keep = {c.id for c in candidates}
        with self.db.transaction() as conn:
            stale = [
                row["id"]
                for row in conn.execute(
                    "SELECT id FROM remediation_candidates WHERE case_id = ? ORDER BY id",
                    (case_id,),
                )
                if row["id"] not in keep
            ]
            conn.executemany(
                "DELETE FROM remediation_candidates WHERE id = ? AND case_id = ?",
                [(candidate_id, case_id) for candidate_id in stale],
            )
            self._upsert_candidates(conn, case_id, candidates)
            if stale:
                append_event(conn, case_id, "candidates:removed", actor, {"candidate_ids": stale})
        return stale

    def refresh_case(
        self,
        case_id: str,
        scan_id: str,
        finding_ids: list[str],
        *,
        actor: str = SYSTEM_ACTOR,
    ) -> RemediationCase:
        """Point a case at a newer scan and its current findings (audited as ``case:refreshed``).

        The status is unchanged; callers only refresh cases still waiting for a human.
        """
        with self.db.transaction() as conn:
            current = self.get(case_id)
            updated = current.model_copy(
                update={
                    "scan_id": scan_id,
                    "finding_ids": list(finding_ids),
                    "updated_at": datetime.now(UTC),
                }
            )
            conn.execute(
                "UPDATE remediation_cases SET scan_id = ? WHERE id = ?", (scan_id, case_id)
            )
            self._write_case(conn, updated)
            append_event(
                conn,
                case_id,
                "case:refreshed",
                actor,
                {
                    "scan_id": scan_id,
                    "previous_scan_id": current.scan_id,
                    "finding_ids": list(finding_ids),
                    "previous_finding_ids": current.finding_ids,
                },
                at=updated.updated_at,
            )
        return updated

    @staticmethod
    def _upsert_candidates(
        conn: sqlite3.Connection, case_id: str, candidates: list[RemediationCandidate]
    ) -> None:
        conn.executemany(
            "INSERT INTO remediation_candidates (id, case_id, position, action_type, "
            "candidate_json) VALUES (?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET "
            "position = excluded.position, action_type = excluded.action_type, "
            "candidate_json = excluded.candidate_json",
            [
                (c.id, case_id, i, c.action_type.value, c.model_dump_json())
                for i, c in enumerate(candidates)
            ],
        )

    def candidates(self, case_id: str) -> list[RemediationCandidate]:
        return [
            RemediationCandidate.model_validate_json(row["candidate_json"])
            for row in self.db.conn.execute(
                "SELECT candidate_json FROM remediation_candidates WHERE case_id = ? "
                "ORDER BY position, id",
                (case_id,),
            )
        ]

    def save_plan(self, plan: RemediationPlan) -> None:
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO remediation_plans (case_id, created_at, plan_json) VALUES (?, ?, ?)",
                (plan.case_id, datetime.now(UTC).isoformat(), plan.model_dump_json()),
            )

    def plan(self, case_id: str) -> RemediationPlan | None:
        """The most recent plan for the case."""
        row = self.db.conn.execute(
            "SELECT plan_json FROM remediation_plans WHERE case_id = ? ORDER BY id DESC LIMIT 1",
            (case_id,),
        ).fetchone()
        return RemediationPlan.model_validate_json(row["plan_json"]) if row else None

    # --- decisions, validation, verification ---------------------------------------------

    def save_decision(self, decision: HumanDecision) -> bool:
        """Record a decision. Returns False when its Jira comment was already recorded."""
        with self.db.transaction() as conn:
            cursor = conn.execute(
                "INSERT OR IGNORE INTO human_decisions (case_id, decision, actor_id, channel, "
                "jira_comment_id, decided_at, decision_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    decision.case_id,
                    decision.decision.value,
                    decision.actor_id,
                    decision.channel,
                    decision.jira_comment_id,
                    decision.decided_at.isoformat(),
                    decision.model_dump_json(),
                ),
            )
            return cursor.rowcount == 1

    def decisions(self, case_id: str) -> list[HumanDecision]:
        return [
            HumanDecision.model_validate_json(row["decision_json"])
            for row in self.db.conn.execute(
                "SELECT decision_json FROM human_decisions WHERE case_id = ? ORDER BY id",
                (case_id,),
            )
        ]

    def save_validation(self, run: ValidationRun) -> None:
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO validation_runs (case_id, started_at, run_json) VALUES (?, ?, ?)",
                (run.case_id, run.started_at.isoformat(), run.model_dump_json()),
            )

    def validations(self, case_id: str) -> list[ValidationRun]:
        return [
            ValidationRun.model_validate_json(row["run_json"])
            for row in self.db.conn.execute(
                "SELECT run_json FROM validation_runs WHERE case_id = ? ORDER BY id", (case_id,)
            )
        ]

    def save_verification(self, result: VerificationResult) -> None:
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO verification_results (case_id, status, result_json) VALUES (?, ?, ?)",
                (result.case_id, result.status.value, result.model_dump_json()),
            )

    def verifications(self, case_id: str) -> list[VerificationResult]:
        return [
            VerificationResult.model_validate_json(row["result_json"])
            for row in self.db.conn.execute(
                "SELECT result_json FROM verification_results WHERE case_id = ? ORDER BY id",
                (case_id,),
            )
        ]

    # --- Jira ----------------------------------------------------------------------------

    def link_jira(self, case_id: str, issue_key: str, actor: str = SYSTEM_ACTOR) -> JiraLink:
        """Link a case to its Jira issue (idempotent) and record the key on the case."""
        now = datetime.now(UTC)
        with self.db.transaction() as conn:
            case = self.get(case_id)
            conn.execute(
                "INSERT INTO jira_links (case_id, issue_key, fingerprint, updated_at) "
                "VALUES (?, ?, ?, ?) ON CONFLICT(case_id) DO UPDATE SET "
                "issue_key = excluded.issue_key, updated_at = excluded.updated_at",
                (case_id, issue_key, case.fingerprint, now.isoformat()),
            )
            if case.jira_key != issue_key:
                self._write_case(conn, case.model_copy(update={"jira_key": issue_key}))
                append_event(conn, case_id, "jira:linked", actor, {"issue_key": issue_key}, at=now)
        link = self.jira_link(case_id)
        if link is None:  # pragma: no cover - just written
            msg = f"Jira link for {case_id} was not stored"
            raise RemediationCaseNotFoundError(msg)
        return link

    def jira_link(self, case_id: str) -> JiraLink | None:
        row = self.db.conn.execute(
            "SELECT * FROM jira_links WHERE case_id = ?", (case_id,)
        ).fetchone()
        return self._link(row) if row else None

    def jira_link_by_issue(self, issue_key: str) -> JiraLink | None:
        row = self.db.conn.execute(
            "SELECT * FROM jira_links WHERE issue_key = ?", (issue_key,)
        ).fetchone()
        return self._link(row) if row else None

    def set_last_synced_comment(self, case_id: str, comment_id: str) -> None:
        with self.db.transaction() as conn:
            cursor = conn.execute(
                "UPDATE jira_links SET last_synced_comment_id = ?, updated_at = ? "
                "WHERE case_id = ?",
                (comment_id, datetime.now(UTC).isoformat(), case_id),
            )
            if cursor.rowcount == 0:
                msg = f"Case {case_id!r} has no Jira link"
                raise RemediationCaseNotFoundError(msg)

    @staticmethod
    def _link(row: sqlite3.Row) -> JiraLink:
        return JiraLink(
            case_id=row["case_id"],
            issue_key=row["issue_key"],
            fingerprint=row["fingerprint"],
            last_synced_comment_id=row["last_synced_comment_id"],
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    # Defined last: inside the class body, later annotations would otherwise see this
    # method instead of the builtin ``list``.
    def list(self, status: CaseStatus | None = None) -> list[RemediationCase]:
        query = "SELECT case_json FROM remediation_cases"
        params: tuple[str, ...] = ()
        if status is not None:
            query += " WHERE status = ?"
            params = (status.value,)
        return [
            RemediationCase.model_validate_json(row["case_json"])
            for row in self.db.conn.execute(f"{query} ORDER BY created_at, id", params)
        ]

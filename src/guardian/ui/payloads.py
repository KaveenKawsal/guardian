"""JSON payloads for the review console API. Read-only; never includes secrets."""

import logging
import threading
from collections.abc import Callable
from typing import Any

from guardian.core.config import GuardianSettings
from guardian.core.models import Finding, RiskAssessment
from guardian.core.remediation_models import RemediationCase
from guardian.execution.runner import ToolRunner
from guardian.integrations.decisions import revalidate_ready
from guardian.integrations.github.records import pull_request_of
from guardian.remediation.compatibility import fix_compatibility
from guardian.storage.database import Database
from guardian.storage.findings import FindingNotFoundError
from guardian.ui.investigation import case_investigation
from guardian.ui.journey import LIVE_STATUSES, build_journey

logger = logging.getLogger(__name__)

RiskLoader = Callable[[Database, str], dict[str, RiskAssessment]]
"""(db, scan_id) -> finding id -> assessment. Rebuilds the knowledge graph, so it is cached."""


def load_scan_risk(db: Database, scan_id: str) -> dict[str, RiskAssessment]:
    """Re-run the deterministic risk model over a stored scan (no I/O beyond the database)."""
    from guardian.knowledge.graph_builder import build_knowledge_graph  # noqa: PLC0415
    from guardian.knowledge.graph_queries import DependencyGraph  # noqa: PLC0415
    from guardian.knowledge.risk import assess  # noqa: PLC0415

    findings = db.findings.load(scan_id)
    index = db.code.load(scan_id)
    graph = DependencyGraph(
        build_knowledge_graph(
            db.scans.profile(scan_id),
            db.sboms.load(scan_id),
            findings,
            db.findings.changes(scan_id),
            code_index=index,
        )
    )
    return {a.finding_id: a for a in assess(findings, graph, index)}


class RiskCache:
    """Per-scan risk assessments, computed once per server run (scans are immutable)."""

    def __init__(self, loader: RiskLoader = load_scan_risk) -> None:
        self._loader = loader
        self._lock = threading.Lock()
        self._cache: dict[str, dict[str, RiskAssessment] | str] = {}

    def get(self, db: Database, scan_id: str) -> dict[str, RiskAssessment] | str:
        """Assessments, or a one-line reason they are unavailable."""
        with self._lock:
            if scan_id in self._cache:
                return self._cache[scan_id]
        try:
            result: dict[str, RiskAssessment] | str = self._loader(db, scan_id)
        except Exception as exc:
            logger.debug("risk breakdown unavailable for %s", scan_id, exc_info=True)
            result = f"Risk breakdown unavailable for this scan ({type(exc).__name__})."
        with self._lock:
            self._cache[scan_id] = result
        return result


def jira_url(settings: GuardianSettings, key: str | None) -> str | None:
    if not key or settings.jira_base_url is None:
        return None
    return f"{str(settings.jira_base_url).rstrip('/')}/browse/{key}"


def case_summary(
    case: RemediationCase, settings: GuardianSettings, *, pending: bool = False
) -> dict[str, Any]:
    return {
        "id": case.id,
        "title": case.title,
        "status": case.status.value,
        "priority": case.priority.value,
        "priority_label": case.priority.label,
        "jira_key": case.jira_key,
        "jira_url": jira_url(settings, case.jira_key),
        "created_at": case.created_at.isoformat(),
        "updated_at": case.updated_at.isoformat(),
        "live": case.status in LIVE_STATUSES or pending,
        "decision_pending": pending,
    }


def case_list(
    db: Database, settings: GuardianSettings, pending: frozenset[str] = frozenset()
) -> list[dict[str, Any]]:
    """Cases sorted by priority (P1 first), then most recently updated."""
    cases = sorted(
        db.remediation.list(), key=lambda c: (c.priority.value, -c.updated_at.timestamp())
    )
    return [case_summary(c, settings, pending=c.id in pending) for c in cases]


def _finding_json(db: Database, scan_id: str, finding_id: str) -> dict[str, Any]:
    try:
        finding: Finding = db.findings.get(scan_id, finding_id)
    except FindingNotFoundError:
        return {"id": finding_id, "missing": True}
    body = finding.model_dump(mode="json")
    body["source"] = "verified"
    return body


def case_detail(
    db: Database,
    case: RemediationCase,
    settings: GuardianSettings,
    risk: RiskCache,
    *,
    pending: bool = False,
) -> dict[str, Any]:
    store = db.remediation
    plan = store.plan(case.id)
    candidates = store.candidates(case.id)
    decisions = store.decisions(case.id)
    validations = store.validations(case.id)
    verifications = store.verifications(case.id)
    events = db.audit.list(case.id)
    link = store.jira_link(case.id)

    assessments = risk.get(db, case.scan_id)
    if isinstance(assessments, str):
        risk_json: list[dict[str, Any]] = []
        risk_note: str | None = assessments
    else:
        risk_json = [
            assessments[f].model_dump(mode="json") for f in case.finding_ids if f in assessments
        ]
        risk_note = None if risk_json else "No risk assessment for this case's findings."

    chosen = plan.chosen_candidate_id if plan is not None else None
    pull_request = pull_request_of(events)
    return {
        "case": case_summary(case, settings, pending=pending)
        | {
            "scan_id": case.scan_id,
            "repository_root": case.repository_root,
            "finding_ids": case.finding_ids,
        },
        "journey": build_journey(
            case, decisions, validations, verifications, events, decision_pending=pending
        ).to_json(),
        "findings": [_finding_json(db, case.scan_id, f) for f in case.finding_ids],
        "risk": risk_json,
        "risk_note": risk_note,
        "candidates": [
            c.model_dump(mode="json") | {"recommended": c.id == chosen} for c in candidates
        ],
        "plan": plan.model_dump(mode="json") if plan is not None else None,
        "decisions": [d.model_dump(mode="json") for d in decisions],
        "validations": [v.model_dump(mode="json") for v in validations],
        "verifications": [v.model_dump(mode="json") for v in verifications],
        "pull_request": pull_request,
        "compatibility": _compatibility(db, case.id),
        "can_revalidate": case.status.value == "AWAITING_DECISION"
        and revalidate_ready(db, case.id),
        "jira": (
            {
                "issue_key": link.issue_key,
                "url": jira_url(settings, link.issue_key),
                "updated_at": link.updated_at.isoformat(),
            }
            if link is not None
            else None
        ),
        "investigation": case_investigation(db, case),
        "audit": [
            {
                "id": e.id,
                "event": e.event,
                "actor": e.actor,
                "at": e.at.isoformat(),
                "payload_sha256": e.payload_sha256,
                "event_sha256": e.event_sha256,
            }
            for e in events
        ],
    }


def _compatibility(db: Database, case_id: str) -> list[dict[str, Any]]:
    """This fix checked against the other fix branches (advisory; never fails the page)."""
    try:
        return [c.to_json() for c in fix_compatibility(db, case_id, ToolRunner())]
    except Exception:
        logger.warning("compatibility check failed for %s", case_id, exc_info=True)
        return []


def audit_status(db: Database) -> dict[str, Any]:
    ok, problems = db.audit.verify()
    count = db.conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
    return {"ok": ok, "events": count, "problems": problems}


def health(db: Database | None, settings: GuardianSettings, error: str | None) -> dict[str, Any]:
    """Booleans and names only: no URL, email, token or approver ids."""
    return {
        "db_ok": db is not None and error is None,
        "db_error": error,
        "jira_configured": settings.jira_configured,
        "cli_approvers_configured": bool(settings.cli_approvers),
        "pr_enabled": settings.pr_enabled,
    }

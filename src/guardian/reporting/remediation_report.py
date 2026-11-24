"""Assemble the report's "Remediation" section from stored cases.

Deterministic: every value is read from the database (cases, candidates, plans, decisions,
validation runs, verification results, the audit log and stored AI investigations). AI output
is copied as labelled inference (rule 10); nothing here calls an LLM or the network.
"""

import json
import re
from collections.abc import Iterable, Mapping
from datetime import UTC, date, datetime
from typing import Any

from guardian.core.config import GuardianSettings
from guardian.core.exceptions import GuardianError
from guardian.core.models import Finding, RiskAssessment
from guardian.core.remediation_models import (
    AuditEvent,
    DeclineReason,
    HumanDecision,
    RemediationCase,
)
from guardian.investigation.models import AGENT_LABELS, AGENTS, InvestigatorReport
from guardian.reporting.models import (
    AcceptedRisk,
    AiStatement,
    AuditChainStatus,
    RemediationCaseReport,
    RemediationSection,
    ReportAuditEvent,
    ReportDecision,
    ReportInvestigation,
)
from guardian.storage.database import Database

PR_OPENED_EVENT = "pr:opened"
REPORTED_AGENTS = frozenset({"dependency", "vulnerability", "code", "correlator"})
_JIRA_KEY = re.compile(r"[A-Z][A-Z0-9_]{0,49}-\d{1,9}")
_AGENT_ORDER = {agent: i for i, agent in enumerate(AGENTS)}
MAX_STATEMENTS = 24


def build_remediation_section(  # noqa: PLR0913 - the report's precomputed scan state
    db: Database,
    scan_id: str,
    findings: Iterable[Finding],
    risks: Mapping[str, RiskAssessment],
    settings: GuardianSettings,
    *,
    today: date | None = None,
) -> RemediationSection | None:
    """The section for every case that belongs to this scan, or None when there is none.

    A case belongs to the scan when it was created/refreshed for it, when one of its findings
    is in the scan, or when the scan is the rescan that verified it.
    """
    scan_findings = {f.id: f for f in findings}
    cases = [c for c in db.remediation.list() if _belongs(db, c, scan_id, scan_findings)]
    if not cases:
        return None
    today = today or datetime.now(UTC).date()
    loader = _FindingLoader(db, scan_findings)
    reports = [_case_report(db, case, scan_id, loader, risks, settings, today) for case in cases]
    reports.sort(key=lambda r: (r.case.priority.value, r.case.created_at, r.case.id))
    ok, problems = db.audit.verify()
    events = int(db.conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0])
    return RemediationSection(
        cases=reports, audit_chain=AuditChainStatus(ok=ok, events=events, problems=problems)
    )


def _belongs(
    db: Database, case: RemediationCase, scan_id: str, scan_findings: Mapping[str, Finding]
) -> bool:
    if case.scan_id == scan_id or any(f in scan_findings for f in case.finding_ids):
        return True
    return any(v.after_scan_id == scan_id for v in db.remediation.verifications(case.id))


class _FindingLoader:
    """Case findings from the report's scan, falling back to the scan the case points at."""

    def __init__(self, db: Database, scan_findings: Mapping[str, Finding]) -> None:
        self.db = db
        self.scan_findings = scan_findings
        self.cache: dict[str, dict[str, Finding]] = {}

    def find(self, case: RemediationCase) -> tuple[list[Finding], list[str]]:
        found: list[Finding] = []
        missing: list[str] = []
        for finding_id in case.finding_ids:
            finding = self.scan_findings.get(finding_id) or self._scan(case.scan_id).get(finding_id)
            if finding is None:
                missing.append(finding_id)
            else:
                found.append(finding)
        return found, missing

    def _scan(self, scan_id: str) -> dict[str, Finding]:
        if scan_id not in self.cache:
            try:
                self.cache[scan_id] = {f.id: f for f in self.db.findings.load(scan_id)}
            except GuardianError:
                self.cache[scan_id] = {}
        return self.cache[scan_id]


def _case_report(  # noqa: PLR0913, PLR0917 - one case's collaborators
    db: Database,
    case: RemediationCase,
    scan_id: str,
    loader: _FindingLoader,
    risks: Mapping[str, RiskAssessment],
    settings: GuardianSettings,
    today: date,
) -> RemediationCaseReport:
    store = db.remediation
    findings, missing = loader.find(case)
    candidates = store.candidates(case.id)
    plan = store.plan(case.id)
    by_id = {c.id: c for c in candidates}
    recommended = by_id.get(plan.chosen_candidate_id) if plan else None
    if recommended is None and candidates and plan is None:
        recommended = candidates[0]
    alternatives = [c for c in candidates if recommended is None or c.id != recommended.id]
    case_jira_url = jira_url(settings, case.jira_key)
    decisions = [_decision(d, case, case_jira_url, today) for d in store.decisions(case.id)]
    verifications = store.verifications(case.id)
    latest = verifications[-1] if verifications else None
    events = db.audit.list(case.id)
    scores = [
        r.score for f in case.finding_ids if (r := risks.get(f)) is not None and r.score is not None
    ]
    risk_before = latest.risk_before if latest and latest.risk_before is not None else None
    if risk_before is None and scores:
        risk_before = max(scores)
    return RemediationCaseReport(
        case=case,
        jira_url=case_jira_url,
        findings=findings,
        missing_finding_ids=missing,
        investigations=_investigations(db, case, scan_id),
        recommended=recommended,
        alternatives=alternatives,
        plan=plan,
        decisions=decisions,
        accepted_risk=_accepted_risk(decisions),
        validations=store.validations(case.id),
        verifications=verifications,
        verdict=latest.status if latest else None,
        risk_before=risk_before,
        risk_after=latest.risk_after if latest else None,
        pull_request_url=_pull_request(events),
        audit=[_audit(e) for e in events],
    )


# --- Decisions -------------------------------------------------------------------------


def jira_url(settings: GuardianSettings, key: str | None) -> str | None:
    """``<base>/browse/<KEY>`` for a well-formed issue key when Jira is configured."""
    if not key or settings.jira_base_url is None or not _JIRA_KEY.fullmatch(key):
        return None
    return f"{str(settings.jira_base_url).rstrip('/')}/browse/{key}"


def _decision(
    decision: HumanDecision, case: RemediationCase, url: str | None, today: date
) -> ReportDecision:
    """Decisions do not store the issue key; a Jira decision was made on the case's issue."""
    expires = decision.risk_acceptance_expires
    via_jira = decision.channel == "jira"
    return ReportDecision(
        decision=decision,
        jira_key=case.jira_key if via_jira else None,
        jira_url=url if via_jira else None,
        expired=None if expires is None else expires < today,
    )


def _accepted_risk(decisions: list[ReportDecision]) -> AcceptedRisk | None:
    for item in reversed(decisions):
        d = item.decision
        if d.decline_reason is DeclineReason.ACCEPTED_RISK and d.risk_acceptance_expires:
            return AcceptedRisk(
                expires=d.risk_acceptance_expires,
                expired=bool(item.expired),
                justification=d.justification,
                actor_display=d.actor_display,
                decided_at=d.decided_at,
            )
    return None


# --- Audit -----------------------------------------------------------------------------


def _audit(event: AuditEvent) -> ReportAuditEvent:
    return ReportAuditEvent(
        id=event.id,
        event=event.event,
        actor=event.actor,
        at=event.at,
        payload_sha256=event.payload_sha256,
        event_sha256=event.event_sha256,
    )


def _pull_request(events: list[AuditEvent]) -> str | None:
    """The URL of the most recent ``pr:opened`` event, if any."""
    for event in reversed(events):
        if event.event != PR_OPENED_EVENT:
            continue
        try:
            payload = json.loads(event.payload_json)
        except ValueError:
            continue
        url = payload.get("url") if isinstance(payload, dict) else None
        if isinstance(url, str) and url:
            return url
    return None


# --- AI investigation ------------------------------------------------------------------


def _investigations(db: Database, case: RemediationCase, scan_id: str) -> list[ReportInvestigation]:
    """Assessments about the case or its findings from the latest investigation run of the
    case's scan and of the report's scan. Reports without AI output are left out."""
    subjects = {case.id, *case.finding_ids}
    chosen: dict[tuple[str, str], InvestigatorReport] = {}
    for sid in dict.fromkeys((scan_id, case.scan_id)):
        run = db.investigations.latest_run(sid)
        if run is None:
            continue
        for report in db.investigations.reports(run.id):
            if (
                report.subject_id in subjects
                and report.agent in REPORTED_AGENTS
                and report.assessment
            ):
                chosen.setdefault((report.agent, report.subject_id), report)
    ordered = sorted(
        chosen.values(),
        key=lambda r: (_AGENT_ORDER.get(r.agent, 99), r.subject_id != case.id, r.subject_id),
    )
    return [_investigation(r) for r in ordered]


def _investigation(report: InvestigatorReport) -> ReportInvestigation:
    return ReportInvestigation(
        agent=report.agent,
        agent_label=AGENT_LABELS.get(report.agent, report.agent),
        subject_kind=report.subject_kind,
        subject_id=report.subject_id,
        status=report.status,
        provider=report.provider,
        model=report.model,
        created_at=report.created_at,
        statements=ai_statements(report.assessment or {})[:MAX_STATEMENTS],
    )


def ai_statements(assessment: Mapping[str, Any]) -> list[AiStatement]:
    """Flatten an ``*Assessment`` dump into labelled statements, keeping evidence refs.

    Claims (``{"text", "evidence_refs"}``), lists of claims, lists of strings and scalars are
    all supported, so a new assessment field shows up without a renderer change.
    """
    out: list[AiStatement] = []
    for key, value in assessment.items():
        if key == "source" or value in (None, "", []):
            continue
        label = key.replace("_", " ").capitalize()
        for item in value if isinstance(value, list) else [value]:
            statement = _statement(label, item)
            if statement is not None:
                out.append(statement)
    return out


def _statement(label: str, item: object) -> AiStatement | None:
    if isinstance(item, Mapping):
        text = item.get("text") or item.get("purpose")
        if not isinstance(text, str) or not text.strip():
            return None
        if isinstance(item.get("area"), str):
            text = f"{item['area']}: {text}"
        refs = item.get("evidence_refs")
        return AiStatement(
            label=label,
            text=text,
            evidence_refs=[str(r) for r in refs] if isinstance(refs, list) else [],
        )
    if isinstance(item, bool):
        return AiStatement(label=label, text="yes" if item else "no")
    if isinstance(item, (str, int, float)):
        return AiStatement(label=label, text=str(item))
    return None

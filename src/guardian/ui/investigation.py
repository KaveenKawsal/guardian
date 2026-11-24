"""Architecture, codebase and AI-investigation payloads for the console, plus the background job
behind ``POST /api/investigate``.

Read-only except for the job, which runs the investigation graph on a worker thread with its own
database connection. Every string from the scan or a model is returned as data; the browser
renders it with ``textContent`` only.
"""

import logging
import threading
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from guardian.core.config import GuardianSettings
from guardian.core.exceptions import GuardianError
from guardian.core.models import CodeDetails, FindingKind, ScanRecord, ToolRunSummary
from guardian.core.remediation_models import CaseStatus, RemediationCase, StepStatus
from guardian.investigation.context import DEFAULT_TOP, area_table, classify_path
from guardian.investigation.models import (
    AGENT_LABELS,
    AGENT_ROLES,
    AGENTS,
    InvestigationRun,
    InvestigatorReport,
    TraceEvent,
)
from guardian.storage.database import Database

logger = logging.getLogger(__name__)

MAX_EVENTS = 400

JobRunner = Callable[[GuardianSettings, int, Callable[[TraceEvent], None]], str]
"""(settings, top, on_event) -> run id. Runs on the worker thread."""


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def default_job(
    settings: GuardianSettings, top: int, on_event: Callable[[TraceEvent], None]
) -> str:
    from guardian.orchestration.investigation_graph import run_investigation  # noqa: PLC0415

    with Database(settings.database_path) as db:
        scan_id = db.scans.resolve("latest")
        run, _ = run_investigation(db, settings, scan_id, top=top, on_event=on_event)
        return run.id


class InvestigationConflictError(GuardianError):
    """An investigation is already running."""


class InvestigationJobs:
    """At most one background investigation at a time; progress kept in memory for polling."""

    def __init__(self, settings: GuardianSettings, runner: JobRunner | None = None) -> None:
        self.settings = settings
        self.runner = runner or default_job
        self._lock = threading.Lock()
        self._running = False
        self._events: list[dict[str, Any]] = []
        self._started_at: datetime | None = None
        self._finished_at: datetime | None = None
        self._error: str | None = None
        self._run_id: str | None = None
        self.thread: threading.Thread | None = None

    def _on_event(self, event: TraceEvent) -> None:
        with self._lock:
            if len(self._events) < MAX_EVENTS:
                self._events.append(event.model_dump(mode="json"))

    def start(self, top: int = DEFAULT_TOP) -> None:
        with self._lock:
            if self._running:
                msg = "An AI investigation is already running."
                raise InvestigationConflictError(msg)
            self._running = True
            self._events = []
            self._error = None
            self._run_id = None
            self._started_at = datetime.now(UTC)
            self._finished_at = None
        self.thread = threading.Thread(target=self._work, args=(top,), daemon=True)
        self.thread.start()

    def _work(self, top: int) -> None:
        run_id: str | None = None
        error: str | None = None
        try:
            run_id = self.runner(self.settings, top, self._on_event)
        except GuardianError as exc:
            error = str(exc)[:300]
        except Exception as exc:
            logger.exception("investigation failed")
            error = f"Investigation failed ({type(exc).__name__})."
        with self._lock:
            self._running = False
            self._run_id = run_id
            self._error = error
            self._finished_at = datetime.now(UTC)

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "running": self._running,
                "started_at": _iso(self._started_at),
                "finished_at": _iso(self._finished_at),
                "run_id": self._run_id,
                "error": self._error,
                "events": list(self._events),
            }


# --- shared --------------------------------------------------------------------------------


def report_json(report: InvestigatorReport) -> dict[str, Any]:
    body = report.model_dump(mode="json")
    body["agent_label"] = AGENT_LABELS[report.agent]
    body["role"] = AGENT_ROLES[report.agent]
    return body


def run_json(run: InvestigationRun | None) -> dict[str, Any] | None:
    if run is None:
        return None
    calls = run.provider_calls
    return {
        "id": run.id,
        "scan_id": run.scan_id,
        "started_at": _iso(run.started_at),
        "finished_at": _iso(run.finished_at),
        "status": run.status,
        "ai_enabled": run.ai_enabled,
        "max_calls": run.max_calls,
        "calls": len(calls),
        "calls_ok": sum(1 for c in calls if c.status == "ok"),
        "latency_seconds": round(sum(c.latency_seconds for c in calls), 2),
        "providers": sorted({f"{c.provider} / {c.model}" for c in calls}),
        "notes": run.notes,
    }


def _latest_scan(db: Database) -> ScanRecord | None:
    try:
        return db.scans.get(db.scans.resolve("latest"))
    except GuardianError:
        return None


# --- case detail ---------------------------------------------------------------------------


def case_investigation(db: Database, case: RemediationCase) -> dict[str, Any] | None:
    """The latest run's reports about this case (or, failing that, about its findings)."""
    run = db.investigations.latest_run(case.scan_id)
    if run is None:
        return None
    reports = db.investigations.reports(run.id, case.id)
    if not reports:
        wanted = set(case.finding_ids)
        reports = [r for r in db.investigations.reports(run.id) if r.subject_id in wanted]
    order = {a: i for i, a in enumerate(AGENTS)}
    reports.sort(key=lambda r: order[r.agent])
    return {"run": run_json(run), "reports": [report_json(r) for r in reports]}


# --- architecture --------------------------------------------------------------------------


def _tool(runs: dict[str, ToolRunSummary], name: str) -> dict[str, Any]:
    run = runs.get(name)
    if run is None:
        return {"tool": name, "status": "not_run", "duration_seconds": None, "error": None}
    return {
        "tool": name,
        "status": run.status,
        "duration_seconds": round(run.duration_seconds, 2),
        "error": run.error,
    }


def _worst(statuses: list[str]) -> str:
    for status in ("failed", "partial", "skipped", "not_run"):
        if status in statuses:
            return status
    return "success" if statuses else "not_run"


def _node(  # noqa: PLR0913, PLR0917 - one diagram node
    node_id: str,
    label: str,
    kind: str,
    status: str,
    summary: str,
    details: list[tuple[str, str]] | None = None,
    **extra: Any,  # noqa: ANN401
) -> dict[str, Any]:
    return {
        "id": node_id,
        "label": label,
        "kind": kind,
        "status": status,
        "summary": summary,
        "details": [[k, v] for k, v in details or [] if v not in (None, "")],
    } | extra


def _tool_node(
    node_id: str, label: str, runs: dict[str, ToolRunSummary], tools: list[str], summary: str
) -> dict[str, Any]:
    entries = [_tool(runs, t) for t in tools]
    details = []
    for t in entries:
        took = f", {t['duration_seconds']:.1f}s" if t["duration_seconds"] is not None else ""
        details.append(
            (t["tool"], f"{t['status']}{took}" + (f": {t['error']}" if t["error"] else ""))
        )
    status = _worst([t["status"] for t in entries if t["status"] != "not_run"] or ["not_run"])
    if len(tools) > 1 and any(t["status"] == "success" for t in entries) and status == "failed":
        status = "partial"
    return _node(node_id, label, "tool", status, summary, details, tools=entries)


def _agent_nodes(
    run: InvestigationRun | None, reports: list[InvestigatorReport], job: dict[str, Any]
) -> list[dict[str, Any]]:
    live = (
        {e.get("agent") or e.get("node") for e in job.get("events", [])}
        if job["running"]
        else set()
    )
    nodes = []
    for agent in AGENTS:
        mine = [r for r in reports if r.agent == agent]
        calls = [c for c in (run.provider_calls if run else []) if c.agent == agent]
        ok = sum(1 for r in mine if r.status in {"ok", "repaired"})
        unavailable = sum(1 for r in mine if r.status == "ai_unavailable")
        if job["running"] and agent in live:
            status = "running"
        elif not mine:
            status = "not_run"
        elif ok and unavailable:
            status = "partial"
        elif ok:
            status = "success"
        else:
            status = "ai_unavailable"
        models = sorted({f"{c.provider} / {c.model}" for c in calls})
        latency = sum(c.latency_seconds for c in calls)
        tokens = sum((c.input_tokens or 0) + (c.output_tokens or 0) for c in calls)
        summary = f"{ok} of {len(mine)} answered" if mine else "Not run yet for this scan"
        reasons = Counter(r.reason for r in mine if r.status == "ai_unavailable" and r.reason)
        nodes.append(
            _node(
                f"agent-{agent}",
                AGENT_LABELS[agent],
                "ai",
                status,
                summary,
                [
                    ("Role", f"{AGENT_ROLES[agent]} model"),
                    ("Reports", str(len(mine))),
                    ("LLM calls", str(len(calls))),
                    ("Provider / model", ", ".join(models) or "none"),
                    ("Model latency", f"{latency:.1f}s" if calls else ""),
                    ("Tokens", str(tokens) if tokens else ""),
                    *((f"Unavailable ({n})", reason) for reason, n in reasons.most_common(2)),
                ],
                agent=agent,
            )
        )
    return nodes


def _pull_request_node(
    db: Database, cases: list[Any], *, pr_enabled: bool | None
) -> dict[str, Any]:
    opened = failed = 0
    for case in cases:
        events = {e.event for e in db.audit.list(case.id)}
        if "pr:opened" in events:
            opened += 1
        elif "pr:failed" in events:
            failed += 1
    if opened:
        status = "success"
    elif failed:
        status = "failed"
    else:
        status = "skipped" if pr_enabled is False else "not_run"
    summary = (
        f"{opened} opened, {failed} failed"
        if opened or failed
        else ("Off (GUARDIAN_PR_ENABLED)" if pr_enabled is False else "No pull request yet")
    )
    return _node(
        "pr",
        "Pull request",
        "remediation",
        status,
        summary,
        [
            ("Opened", str(opened)),
            ("Failed", str(failed)),
            ("Rule", "Only after a human ACCEPT/MODIFY and a VERIFIED verdict; never merged"),
        ],
    )


def architecture(
    db: Database,
    risk: Any,  # noqa: ANN401 - payloads.RiskCache (circular import avoided)
    job: dict[str, Any],
    *,
    pr_enabled: bool | None = None,
) -> dict[str, Any]:
    """Guardian's real pipeline for the latest scan, each node with live status from data."""
    scan = _latest_scan(db)
    if scan is None:
        return {"scan": None, "nodes": [], "edges": [], "investigation": None, "job": job}
    runs = {r.tool: r for r in scan.tool_runs}
    findings = db.findings.load(scan.id)
    kinds = Counter(f.kind for f in findings)
    index = db.code.load(scan.id)
    profile = db.scans.profile(scan.id)
    run = db.investigations.latest_run(scan.id)
    reports = db.investigations.reports(run.id) if run is not None else []

    assessments = risk.get(db, scan.id)
    priorities = (
        Counter(a.priority.value for a in assessments.values())
        if isinstance(assessments, dict)
        else Counter()
    )
    cases = db.remediation.list()
    by_status = Counter(c.status.value for c in cases)
    decisions = [d for c in cases for d in db.remediation.decisions(c.id)]
    validations = [v for c in cases for v in db.remediation.validations(c.id)]
    verifications = [v for c in cases for v in db.remediation.verifications(c.id)]
    steps = Counter(s.status.value for v in validations for s in v.steps)
    verdicts = Counter(v.status.value for v in verifications)
    sbom_components = scan.component_count

    nodes = [
        _node(
            "profile",
            "Profile",
            "tool",
            "success",
            f"{len(profile.languages)} languages, {len(profile.ecosystems)} ecosystems",
            [
                ("Languages", ", ".join(lang.name for lang in profile.languages[:6])),
                ("Ecosystems", ", ".join(e.ecosystem.value for e in profile.ecosystems)),
                ("Files", str(profile.total_files)),
            ],
        ),
        _tool_node(
            "sbom",
            "SBOM",
            runs,
            ["npm-lockfile", "cdxgen"],
            f"{sbom_components} components",
        ),
        _tool_node(
            "osv",
            "OSV",
            runs,
            ["osv-scanner"],
            f"{kinds.get(FindingKind.VULNERABILITY, 0)} known vulnerabilities",
        ),
        _tool_node(
            "semgrep",
            "Semgrep",
            runs,
            ["semgrep"],
            f"{kinds.get(FindingKind.CODE, 0)} code findings",
        ),
        _tool_node(
            "git", "Git history", runs, ["git"], f"{kinds.get(FindingKind.CHANGE, 0)} risky changes"
        ),
        _tool_node(
            "indexer",
            "Code indexer",
            runs,
            ["indexer"],
            f"{len(index.files)} files, {len(index.entry_points)} entry points"
            if index is not None
            else "no code index",
        ),
        _node(
            "graph",
            "Knowledge graph",
            "derived",
            "success" if scan.component_count or findings else "skipped",
            "Components, findings, imports and calls linked",
            [
                ("Components", str(sbom_components)),
                ("Findings", str(len(findings))),
                ("Imports indexed", str(len(index.imports)) if index is not None else "0"),
            ],
        ),
        _node(
            "risk",
            "Risk scoring",
            "derived",
            "success" if priorities else ("skipped" if not findings else "failed"),
            ", ".join(f"{p} {n}" for p, n in sorted(priorities.items())) or "No findings to score",
            [(p, str(n)) for p, n in sorted(priorities.items())]
            + ([("Note", assessments)] if isinstance(assessments, str) else []),
        ),
        *_agent_nodes(run, reports, job),
        _node(
            "cases",
            "Remediation cases",
            "remediation",
            "success" if cases else "not_run",
            f"{len(cases)} cases" if cases else "No cases yet",
            [(s.replace("_", " ").lower(), str(n)) for s, n in sorted(by_status.items())],
        ),
        _node(
            "decision",
            "Human decision",
            "human",
            "waiting"
            if by_status.get(CaseStatus.AWAITING_DECISION.value)
            else ("success" if decisions else "not_run"),
            f"{by_status.get(CaseStatus.AWAITING_DECISION.value, 0)} waiting, "
            f"{len(decisions)} recorded",
            [
                (
                    "Waiting for a decision",
                    str(by_status.get(CaseStatus.AWAITING_DECISION.value, 0)),
                ),
                *(
                    (f"Via {channel}", str(n))
                    for channel, n in sorted(Counter(d.channel for d in decisions).items())
                ),
                ("Channels", "Jira comment or this console, same strict grammar and allowlist"),
            ],
        ),
        _node(
            "apply",
            "Apply in worktree",
            "remediation",
            "success" if validations else "not_run",
            f"{len(validations)} isolated branches",
            [("Branches", ", ".join(sorted({v.branch for v in validations})[:4]))],
        ),
        _node(
            "sandbox",
            "Sandbox build & test",
            "remediation",
            "failed"
            if steps.get(StepStatus.FAILED.value) and not steps.get(StepStatus.PASSED.value)
            else ("success" if steps else "not_run"),
            ", ".join(f"{n} {s}" for s, n in sorted(steps.items())) or "Not run yet",
            [(s, str(n)) for s, n in sorted(steps.items())],
        ),
        _node(
            "rescan",
            "Rescan",
            "remediation",
            "success" if verifications else "not_run",
            f"{len(verifications)} before/after comparisons",
        ),
        _node(
            "verdict",
            "Verdict",
            "remediation",
            "success" if verdicts.get("VERIFIED") else ("failed" if verdicts else "not_run"),
            ", ".join(f"{n} {s.lower().replace('_', ' ')}" for s, n in sorted(verdicts.items()))
            or "No verdict yet",
            [(s.lower().replace("_", " "), str(n)) for s, n in sorted(verdicts.items())],
        ),
        _pull_request_node(db, cases, pr_enabled=pr_enabled),
    ]
    edges = [
        ["profile", "sbom"],
        ["sbom", "osv"],
        ["profile", "semgrep"],
        ["profile", "git"],
        ["profile", "indexer"],
        ["osv", "graph"],
        ["semgrep", "graph"],
        ["git", "graph"],
        ["indexer", "graph"],
        ["graph", "risk"],
        *(["risk", f"agent-{a}"] for a in ("architect", "dependency", "vulnerability", "code")),
        *(
            [f"agent-{a}", "agent-correlator"]
            for a in ("architect", "dependency", "vulnerability", "code")
        ),
        ["risk", "cases"],
        ["agent-correlator", "cases"],
        ["cases", "decision"],
        ["decision", "apply"],
        ["apply", "sandbox"],
        ["sandbox", "rescan"],
        ["rescan", "verdict"],
        ["verdict", "pr"],
    ]
    return {
        "scan": {
            "id": scan.id,
            "repository": scan.repository_name,
            "status": scan.status.value,
            "started_at": _iso(scan.started_at),
            "git_commit": scan.git_commit,
        },
        "nodes": nodes,
        "edges": edges,
        "investigation": run_json(run),
        "job": job,
    }


# --- codebase ------------------------------------------------------------------------------


def codebase(db: Database, risk: Any) -> dict[str, Any]:  # noqa: ANN401 - payloads.RiskCache
    scan = _latest_scan(db)
    if scan is None:
        return {"scan": None}
    profile = db.scans.profile(scan.id)
    index = db.code.load(scan.id)
    findings = db.findings.load(scan.id)
    run = db.investigations.latest_run(scan.id)
    reports = db.investigations.reports(run.id) if run is not None else []
    by_subject: dict[str, dict[str, InvestigatorReport]] = {}
    for r in reports:
        by_subject.setdefault(r.subject_id, {})[r.agent] = r
    architect = by_subject.get(scan.id, {}).get("architect")
    ai_modules = (
        {m["area"]: m for m in (architect.assessment or {}).get("modules", [])}
        if architect is not None
        else {}
    )

    modules = []
    for row in area_table(index):
        ai = ai_modules.get(row["area"])
        modules.append(
            row
            | {
                "ai": (
                    {
                        "purpose": ai["purpose"],
                        "kind": ai["kind"],
                        "evidence_refs": ai["evidence_refs"],
                    }
                    if ai
                    else None
                )
            }
        )
    assessments = risk.get(db, scan.id)
    scores = assessments if isinstance(assessments, dict) else {}

    def score_of(fid: str) -> float:
        a = scores.get(fid)
        return a.score if a is not None and a.score is not None else -1.0

    code = sorted(
        (f for f in findings if f.kind is FindingKind.CODE),
        key=lambda f: (-score_of(f.id), -f.severity.rank, f.path or "", f.start_line or 0),
    )
    rows = []
    for f in code:
        d = f.details
        a = scores.get(f.id)
        mine = by_subject.get(f.id, {})
        rows.append(
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "rule_id": d.rule_id if isinstance(d, CodeDetails) else None,
                "message": d.message if isinstance(d, CodeDetails) else None,
                "location": f"{f.path}:{f.start_line}" if f.path and f.start_line else f.path,
                "path_classification": classify_path(f.path) if f.path else "unknown",
                "risk": (
                    {"score": a.score, "priority": a.priority.value, "summary": a.summary}
                    if a is not None
                    else None
                ),
                "code_investigator": report_json(mine["code"]) if "code" in mine else None,
                "correlator": report_json(mine["correlator"]) if "correlator" in mine else None,
            }
        )
    entry_kinds = Counter(e.kind.value for e in index.entry_points) if index is not None else {}
    return {
        "scan": {
            "id": scan.id,
            "repository": scan.repository_name,
            "root": scan.repository_root,
            "started_at": _iso(scan.started_at),
            "git_branch": scan.git_branch,
            "git_commit": scan.git_commit,
        },
        "profile": {
            "languages": [
                {"name": lang.name, "files": lang.files} for lang in profile.languages[:10]
            ],
            "ecosystems": [
                {
                    "ecosystem": e.ecosystem.value,
                    "package_managers": e.package_managers,
                    "frameworks": [fw.name for fw in e.frameworks],
                }
                for e in profile.ecosystems
            ],
            "total_files": profile.total_files,
            "indexed_files": len(index.files) if index is not None else 0,
            "entry_points": len(index.entry_points) if index is not None else 0,
            "entry_points_by_kind": dict(entry_kinds),
        },
        "modules": modules,
        "architect": report_json(architect) if architect is not None else None,
        "code_findings": rows,
        "investigation": run_json(run),
    }

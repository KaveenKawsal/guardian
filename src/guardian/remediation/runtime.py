"""The live remediation runtime: real services behind the remediation graph, and the one entry
point every decision channel uses.

```
guardian remediate      -> start_cases()      plan -> publish_jira -> await_decision (interrupt)
guardian decide / validate,
Jira sync, web UI       -> submit_decision()  resume -> apply -> validate -> rescan_verify -> ...
```

``GuardianServices`` implements ``RemediationServices`` with the real code: the planner, Jira
publish/write-back, ``apply_case`` in a ``guardian/fix-*`` worktree, ``validate_case`` in the
Docker sandbox, ``verify_case`` with a full rescan and, when ``GUARDIAN_PR_ENABLED`` is on, a
GitHub pull request for a VERIFIED fix (``integrations/github``). Each method is idempotent
(a replayed node calls it again) and turns expected failures into ``GuardianError``
subclasses, which the graph routes back to human review. Jira is best effort here: a Jira
outage is audited and never stops the remediation.

Threads: graph nodes run on the calling thread and ``Database`` connections are bound to the
thread that opened them, so ``submit_decision`` opens its own database and checkpointer inside
the call. That makes it safe to call from the UI's worker thread. A process-wide per-case lock
keeps two submits for the same case from interleaving; across processes, SQLite's write lock and
busy timeout serialise the writes and ``resume_case`` refuses a thread that already moved on.
"""

import json
import threading
from collections.abc import Callable, Generator, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from functools import partial
from pathlib import Path
from typing import Any

import httpx

from guardian.core.config import GuardianSettings
from guardian.core.exceptions import GuardianError
from guardian.core.models import Priority
from guardian.core.remediation_models import (
    CaseStatus,
    DecisionType,
    HumanDecision,
    RemediationCase,
    ValidationRun,
)
from guardian.execution.runner import ToolRunner
from guardian.integrations.github.pr import open_pull_request
from guardian.integrations.github.remote import PrError
from guardian.integrations.jira import adf
from guardian.integrations.jira.client import JiraClient, jira_client_from_settings
from guardian.integrations.jira.publish import (
    CaseContext,
    load_case_contexts,
    publish_case,
    select_for_publishing,
)
from guardian.integrations.jira.writeback import (
    Stage,
    applying_body,
    comment_stage,
    failure_body,
    pr_failed_body,
    pr_opened_body,
    validation_body,
    verification_body,
)
from guardian.orchestration.checkpoint import checkpoint_path, open_checkpointer
from guardian.orchestration.remediation_graph import (
    CaseNotAwaitingDecisionError,
    InterruptInfo,
    RemediationGraph,
    RunResult,
    build_remediation_graph,
    continue_case,
    is_awaiting_decision,
    resume_case,
    start_case,
)
from guardian.orchestration.services import RemediationServices
from guardian.remediation.apply import AppliedChange, ApplyFn, RemediationApplyError, apply_case
from guardian.remediation.candidates import RegistryLike
from guardian.remediation.cases import create_cases
from guardian.remediation.lockfile import generate_npm_lockfile
from guardian.remediation.registry import NpmRegistry
from guardian.remediation.sandbox import DockerSandbox, Sandbox, SandboxConfig
from guardian.remediation.validate import validate_case
from guardian.remediation.verify import ScanFn, default_scan_fn, verify_case
from guardian.storage.database import Database
from guardian.storage.remediation import SYSTEM_ACTOR

LockfileGenerator = Callable[[Path, Path], tuple[Path | None, str | None]]
JiraFactory = Callable[[GuardianSettings], JiraClient]
DecisionHandler = Callable[[RemediationCase, HumanDecision], None]

DECLINE_EVENT = "decline:recorded"
_OPEN = frozenset({CaseStatus.PROPOSED, CaseStatus.AWAITING_DECISION})


class DecisionNotApplicableError(GuardianError):
    """The decision cannot be handed to the case's graph thread in its current state."""


class RemediationValidationError(GuardianError):
    """Validation could not run at all (e.g. the worktree copy failed)."""


# --- settings -> collaborators ----------------------------------------------------------


def sandbox_config(settings: GuardianSettings) -> SandboxConfig:
    return SandboxConfig(
        cpus=settings.sandbox_cpus,
        memory=settings.sandbox_memory,
        install_timeout_seconds=settings.sandbox_timeout_seconds,
        step_timeout_seconds=settings.sandbox_timeout_seconds,
    )


def docker_sandbox(settings: GuardianSettings) -> DockerSandbox:
    return DockerSandbox(config=sandbox_config(settings))


def lockfile_generator_for(
    settings: GuardianSettings, sandbox: Sandbox
) -> LockfileGenerator | None:
    """``ScanPipeline``'s lockfile hook bound to ``sandbox``; None when generation is off."""
    if not settings.npm_lockfile_generation:
        return None
    return partial(generate_npm_lockfile, sandbox=sandbox)


def default_registry(settings: GuardianSettings) -> NpmRegistry:
    return NpmRegistry(settings.data_dir / "cache" / "npm-registry")


def applied_to_json(applied: AppliedChange) -> dict[str, Any]:
    data = asdict(applied)
    data["worktree_path"] = str(applied.worktree_path)
    return data


def applied_from_json(data: dict[str, Any]) -> AppliedChange:
    if "error" in data or "worktree_path" not in data:
        msg = f"No applied change to work on ({data.get('error', 'missing worktree')})"
        raise RemediationApplyError(msg)
    return AppliedChange(
        case_id=str(data["case_id"]),
        branch=str(data["branch"]),
        worktree_path=Path(data["worktree_path"]),
        commit_sha=str(data["commit_sha"]),
        base_commit=str(data["base_commit"]),
        changed_paths=[str(p) for p in data.get("changed_paths") or []],
        candidate_id=data.get("candidate_id"),
        manual_ref=data.get("manual_ref"),
    )


# --- services ---------------------------------------------------------------------------


class GuardianServices:
    """The real ``RemediationServices``. Every collaborator is injectable for tests."""

    def __init__(  # noqa: PLR0913 - every collaborator is injectable for tests
        self,
        db: Database,
        settings: GuardianSettings,
        *,
        jira_enabled: bool = True,
        sandbox: Sandbox | None = None,
        host_sandbox: Sandbox | None = None,
        runner: ToolRunner | None = None,
        apply_fn: ApplyFn | None = None,
        scan_fn: ScanFn | None = None,
        registry: RegistryLike | None = None,
        jira_factory: JiraFactory | None = None,
        push_runner: ToolRunner | None = None,
        github_http: httpx.Client | None = None,
    ) -> None:
        self.db = db
        self.settings = settings
        self.jira_enabled = jira_enabled and settings.jira_configured
        self.sandbox: Sandbox = sandbox or docker_sandbox(settings)
        self.host_sandbox = host_sandbox
        self.runner = runner or ToolRunner()
        self.apply_fn = apply_fn
        self._scan_fn = scan_fn
        self._registry = registry
        self._jira_factory = jira_factory or jira_client_from_settings
        self._jira: JiraClient | None = None
        self.push_runner = push_runner
        self.github_http = github_http

    def close(self) -> None:
        if self._jira is not None:
            self._jira.close()
            self._jira = None

    # --- helpers -------------------------------------------------------------------------

    @property
    def scan_fn(self) -> ScanFn:
        if self._scan_fn is None:
            self._scan_fn = default_scan_fn(
                self.db,
                self.settings,
                lockfile_generator=lockfile_generator_for(self.settings, self.sandbox),
            )
        return self._scan_fn

    def _jira_client(self) -> JiraClient:
        if self._jira is None:
            self._jira = self._jira_factory(self.settings)
        return self._jira

    def _jira_problem(self, case_id: str, event: str, exc: Exception) -> None:
        self.db.audit.append(
            case_id, event, SYSTEM_ACTOR, {"error": " ".join(str(exc).split())[:300]}
        )

    def _comment(
        self,
        case_id: str,
        stage: Stage,
        body: adf.Node,
        *,
        key: str,
        transition: Any = None,  # noqa: ANN401 - JiraTransitionEvent | None
    ) -> None:
        """Best-effort, idempotent stage comment on the case's issue (no-op without a link)."""
        if not self.jira_enabled:
            return
        link = self.db.remediation.jira_link(case_id)
        if link is None:
            return
        try:
            comment_stage(
                self.db,
                self._jira_client(),
                link,
                stage,
                body,
                key=key,
                settings=self.settings,
                transition=transition,
            )
        except GuardianError as exc:
            self._jira_problem(case_id, "jira:comment_failed", exc)

    # --- RemediationServices -------------------------------------------------------------

    def plan(self, case_id: str) -> None:
        """Candidates and a plan normally exist (``guardian remediate``); rebuild them from the
        case's scan only when they are missing. Never calls an LLM from the graph."""
        case = self.db.remediation.get(case_id)
        plan = self.db.remediation.plan(case_id)
        candidate_ids = {c.id for c in self.db.remediation.candidates(case_id)}
        if plan is not None and plan.chosen_candidate_id in candidate_ids:
            return
        create_cases(
            self.db,
            case.scan_id,
            settings=self.settings,
            registry=self._registry or default_registry(self.settings),
            min_priority=Priority.P4,
            top=1,
            finding_ids=case.finding_ids,
            no_ai=True,
        )

    def publish(self, case_id: str) -> str | None:
        if not self.jira_enabled:
            return None
        case = self.db.remediation.get(case_id)
        if self.db.remediation.jira_link(case_id) is None:
            peers = [c for c in self.db.remediation.list() if c.scan_id == case.scan_id]
            if case.id not in {c.id for c in select_for_publishing(peers, self.settings)}:
                return None  # below GUARDIAN_JIRA_MIN_PRIORITY or past the cap
        try:
            context = load_case_contexts(self.db, case.scan_id, [case.id]).get(
                case.id
            ) or CaseContext([], [], [], None)
            link = publish_case(
                self.db,
                self._jira_client(),
                self.settings,
                case,
                findings=context.findings,
                assessments=context.assessments,
                candidates=context.candidates,
                plan=context.plan,
                dependency_paths=context.dependency_paths,
            )
        except GuardianError as exc:
            self._jira_problem(case_id, "jira:publish_failed", exc)
            link = self.db.remediation.jira_link(case_id)
            return link.issue_key if link else None
        return link.issue_key

    def notify(self, case_id: str, stage: str, payload: dict) -> None:
        attempt = payload.get("attempt", 1)
        reasons = [str(r) for r in payload.get("reasons") or []]
        if stage == "failed":
            summary = str(payload.get("error") or payload.get("reason") or "validation failed")
            self._comment(
                case_id,
                "failure",
                failure_body(summary, reasons),
                key=f"attempt-{attempt}",
                transition="validation_failed",
            )
        elif stage == "verified":
            results = self.db.remediation.verifications(case_id)
            body = (
                verification_body(results[-1])
                if results
                else adf.doc(adf.paragraph(adf.strong("Verified.")))
            )
            self._comment(
                case_id, "verification", body, key=f"attempt-{attempt}", transition="verified"
            )
        elif stage == "pr_opened":
            url = str(payload.get("url") or "")
            self._comment(
                case_id,
                "pr_opened",
                pr_opened_body(
                    url,
                    payload.get("number"),
                    draft=bool(payload.get("draft")),
                    reused=bool(payload.get("reused")),
                ),
                key=url or f"attempt-{attempt}",
            )
        elif stage == "pr_failed":
            self._comment(
                case_id,
                "pr_failed",
                pr_failed_body(str(payload.get("error") or "unknown error")),
                key=f"attempt-{attempt}",
            )
        elif stage == "declined":
            reason = payload.get("decline_reason") or "declined"
            body = adf.doc(
                adf.paragraph(
                    adf.strong("Declined: "),
                    adf.code(str(reason)),
                    ". The case is closed; no change was made.",
                )
            )
            self._comment(
                case_id, "acknowledged", body, key=f"declined-{attempt}", transition="declined"
            )

    def apply(self, case_id: str, decision: HumanDecision) -> dict:
        case = self.db.remediation.get(case_id)
        repo_root = Path(case.repository_root)
        if not repo_root.is_dir():
            msg = f"Repository {repo_root} is not available on this machine"
            raise RemediationApplyError(msg)
        try:
            with repository_lock(repo_root):
                applied = apply_case(
                    self.db,
                    case,
                    None,
                    decision,
                    repo_root=repo_root,
                    guardian_home=self.settings.data_dir,
                    runner=self.runner,
                    apply_fn=self.apply_fn,
                    actor=f"{decision.channel}:{decision.actor_id}",
                )
        except OSError as exc:
            msg = f"Could not prepare the fix worktree: {exc}"
            raise RemediationApplyError(msg) from exc
        self._comment(
            case_id,
            "applying",
            applying_body(applied.branch, applied.candidate_id),
            key=applied.commit_sha,
            transition="approved",
        )
        return applied_to_json(applied)

    def validate(self, case_id: str, applied: dict) -> dict:
        case = self.db.remediation.get(case_id)
        change = applied_from_json(applied)
        try:
            with sandbox_slot(self.settings):
                run = validate_case(
                    self.db,
                    case,
                    change,
                    sandbox=self.sandbox,
                    unsafe_host=self.settings.unsafe_host_validation,
                    host_sandbox=self.host_sandbox,
                    log_root=self.settings.data_dir / "logs",
                )
        except (OSError, ValueError) as exc:
            msg = f"Validation could not run: {exc}"
            raise RemediationValidationError(msg) from exc
        self._comment(case_id, "validation", validation_body(run), key=run.started_at.isoformat())
        return run.model_dump(mode="json")

    def verify(self, case_id: str, applied: dict, validation: dict) -> dict:
        case = self.db.remediation.get(case_id)
        with sandbox_slot(self.settings):
            result = verify_case(
                self.db,
                case,
                applied_from_json(applied),
                ValidationRun.model_validate(validation),
                before_scan_id=case.scan_id,
                scan_fn=self.scan_fn,
            )
        return result.model_dump(mode="json")

    def open_pr(self, case_id: str, applied: dict, verification: dict) -> dict | None:
        """Push the verified branch and open its pull request (None when disabled)."""
        if not self.settings.pr_enabled:
            return None
        repo_root = Path(self.db.remediation.get(case_id).repository_root)
        try:
            with repository_lock(repo_root):
                return open_pull_request(
                    self.db,
                    self.settings,
                    case_id,
                    applied,
                    verification,
                    runner=self.runner,
                    push_runner=self.push_runner,
                    http_client=self.github_http,
                )
        except (OSError, ValueError) as exc:
            msg = f"Could not open the pull request: {type(exc).__name__}: {exc}"
            raise PrError(msg) from exc

    def record_acceptance(self, case_id: str, decision: HumanDecision) -> None:
        """Audit the decline once per decision, with the accepted-risk expiry for reports."""
        decided_at = decision.decided_at.isoformat()
        for event in self.db.audit.list(case_id):
            if (
                event.event == DECLINE_EVENT
                and json.loads(event.payload_json).get("decided_at") == decided_at
            ):
                return
        expires = decision.risk_acceptance_expires
        self.db.audit.append(
            case_id,
            DECLINE_EVENT,
            f"{decision.channel}:{decision.actor_id}",
            {
                "decided_at": decided_at,
                "decline_reason": decision.decline_reason.value
                if decision.decline_reason
                else None,
                "risk_acceptance_expires": expires.isoformat() if expires else None,
                "justification": decision.justification,
                "jira_comment_id": decision.jira_comment_id,
            },
        )


def build_services(
    db: Database, settings: GuardianSettings, *, jira_enabled: bool = True
) -> RemediationServices:
    """The services every runtime uses (tests replace this function)."""
    return GuardianServices(db, settings, jira_enabled=jira_enabled)


# --- runtime ----------------------------------------------------------------------------

_LOCKS: dict[str, threading.RLock] = {}
_LOCKS_GUARD = threading.Lock()
_REPO_LOCKS: dict[str, threading.Lock] = {}
_SLOTS: dict[int, threading.BoundedSemaphore] = {}


@contextmanager
def repository_lock(repo_root: Path) -> Generator[None]:
    """Serialise git changes to one repository (worktree add/remove, branch delete, push).

    Fixes for different cases run in parallel, but they share the repository's ``.git``:
    concurrent ``git worktree add`` calls race on its lock files.
    """
    key = str(repo_root.resolve())
    with _LOCKS_GUARD:
        lock = _REPO_LOCKS.setdefault(key, threading.Lock())
    with lock:
        yield


@contextmanager
def sandbox_slot(settings: GuardianSettings) -> Generator[None]:
    """At most ``max_parallel_fixes`` sandbox builds/tests and rescans at a time; each holds
    its own CPU and memory limits, so this bounds the total load on the machine."""
    with _LOCKS_GUARD:
        slots = _SLOTS.setdefault(
            settings.max_parallel_fixes, threading.BoundedSemaphore(settings.max_parallel_fixes)
        )
    with slots:
        yield


@contextmanager
def case_lock(case_id: str) -> Generator[None]:
    """Serialise graph runs for one case inside this process."""
    with _LOCKS_GUARD:
        lock = _LOCKS.setdefault(case_id, threading.RLock())
    with lock:
        yield


@contextmanager
def _runtime(
    settings: GuardianSettings, *, jira_enabled: bool
) -> Generator[tuple[Database, RemediationGraph, RemediationServices]]:
    with (
        Database(settings.database_path) as db,
        open_checkpointer(checkpoint_path(settings.data_dir)) as saver,
    ):
        services = build_services(db, settings, jira_enabled=jira_enabled)
        try:
            yield db, build_remediation_graph(db, services, saver), services
        finally:
            close = getattr(services, "close", None)
            if callable(close):
                close()


@contextmanager
def open_runtime(
    settings: GuardianSettings, *, jira_enabled: bool = True
) -> Generator[tuple[Database, RemediationGraph]]:
    """A database and a compiled remediation graph with the durable SQLite checkpointer.

    Both belong to the calling thread; open a new runtime on every worker thread.
    """
    with _runtime(settings, jira_enabled=jira_enabled) as (db, graph, _):
        yield db, graph


def thread_exists(graph: RemediationGraph, case_id: str) -> bool:
    snapshot = graph.get_state({"configurable": {"thread_id": case_id}})
    return bool(snapshot.values) or bool(snapshot.next)


def has_crashed_step(graph: RemediationGraph, case_id: str) -> bool:
    """The thread stopped on an exception (pending node, no interrupt)."""
    snapshot = graph.get_state({"configurable": {"thread_id": case_id}})
    return bool(snapshot.next) and not is_awaiting_decision(graph, case_id)


@dataclass(frozen=True)
class StartResult:
    case_id: str
    interrupt: InterruptInfo | None
    jira_key: str | None = None
    error: str | None = None


def start_cases(
    settings: GuardianSettings, case_ids: Sequence[str], *, jira_enabled: bool = True
) -> list[StartResult]:
    """Run each open case's thread up to ``await_decision`` (plan -> publish -> interrupt).

    A thread that already exists is not restarted; a case refreshed by a newer scan gets its
    Jira issue updated instead. One failing case does not stop the others.
    """
    results: list[StartResult] = []
    with _runtime(settings, jira_enabled=jira_enabled) as (db, graph, services):
        for case_id in case_ids:
            with case_lock(case_id):
                try:
                    if db.remediation.get(case_id).status not in _OPEN:
                        continue
                    existed = thread_exists(graph, case_id)
                    info = start_case(graph, case_id)
                    jira_key = info.payload.get("jira_key") if info else None
                    if existed and is_awaiting_decision(graph, case_id):
                        jira_key = services.publish(case_id) or jira_key
                    results.append(StartResult(case_id, info, jira_key))
                except Exception as exc:  # noqa: BLE001 - reported per case, others continue
                    message = f"{type(exc).__name__}: {' '.join(str(exc).split())[:300]}"
                    results.append(StartResult(case_id, None, error=message))
    return results


def _check_revalidate(graph: RemediationGraph, case_id: str) -> None:
    values = graph.get_state({"configurable": {"thread_id": case_id}}).values
    previous = values.get("decision") or {}
    if previous.get("decision") not in {DecisionType.ACCEPT.value, DecisionType.MODIFY.value}:
        msg = (
            f"Case {case_id} has no earlier ACCEPT/MODIFY attempt to re-validate; "
            "use accept or modify"
        )
        raise DecisionNotApplicableError(msg)


def submit_decision(
    settings: GuardianSettings,
    case_id: str,
    decision: HumanDecision,
    *,
    already_recorded: bool = False,
    jira_enabled: bool = True,
) -> RunResult:
    """Record (unless ``already_recorded``) a parsed, authorized decision and resume the case's
    graph thread with it. Blocks until the thread pauses again or finishes; that can take
    minutes (worktree, Docker build and tests, rescan).

    Raises ``DecisionNotApplicableError`` / ``CaseNotAwaitingDecisionError`` (nothing recorded)
    when the case is not waiting for a human, and ``ValueError`` for a decision naming another
    case. Safe to call from a worker thread: everything is opened inside the call.
    """
    if decision.case_id != case_id:
        msg = f"Decision is for {decision.case_id}, not {case_id}"
        raise ValueError(msg)
    with (
        case_lock(case_id),
        _runtime(settings, jira_enabled=jira_enabled) as (db, graph, _),
    ):
        case = db.remediation.get(case_id)
        if case.status is not CaseStatus.AWAITING_DECISION:
            msg = f"Case {case_id} is {case.status.value}, not AWAITING_DECISION"
            raise DecisionNotApplicableError(msg)
        if not thread_exists(graph, case_id):
            start_case(graph, case_id)
        if not is_awaiting_decision(graph, case_id):
            hint = (
                f"; run `guardian validate {case_id}` to retry its crashed step"
                if has_crashed_step(graph, case_id)
                else ""
            )
            msg = f"Case {case_id} is not paused for a decision{hint}"
            raise CaseNotAwaitingDecisionError(msg)
        if decision.decision is DecisionType.REVALIDATE:
            _check_revalidate(graph, case_id)
        if not already_recorded:
            db.remediation.save_decision(decision)
            db.audit.append(
                case_id, "decision:recorded", f"{decision.channel}:{decision.actor_id}", decision
            )
        return resume_case(graph, case_id, decision)


def retry_case(settings: GuardianSettings, case_id: str, *, jira_enabled: bool = True) -> RunResult:
    """Re-run the step a crash left pending (``continue_case``)."""
    with (
        case_lock(case_id),
        _runtime(settings, jira_enabled=jira_enabled) as (_, graph, _services),
    ):
        return continue_case(graph, case_id)


def case_has_crashed_step(settings: GuardianSettings, case_id: str) -> bool:
    with open_runtime(settings, jira_enabled=False) as (_, graph):
        return has_crashed_step(graph, case_id)


def make_ui_decision_handler(settings: GuardianSettings) -> DecisionHandler:
    """Handler for the web UI: it has already saved and audited the decision, and calls this on
    a worker thread, so ``submit_decision`` opens its own connections."""

    def handle(case: RemediationCase, decision: HumanDecision) -> None:
        submit_decision(settings, case.id, decision, already_recorded=True)

    return handle

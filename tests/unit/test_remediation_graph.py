"""Remediation graph B: durable interrupt/resume with a real SqliteSaver and a real Database."""

from collections import Counter
from contextlib import ExitStack
from datetime import UTC, date, datetime

import pytest

from guardian.core.exceptions import GuardianError
from guardian.core.models import GitInfo, Priority, RepositoryProfile
from guardian.core.remediation_models import (
    CaseStatus,
    DecisionType,
    DeclineReason,
    HumanDecision,
    ModifyPayload,
    RemediationCase,
    case_id_for,
    fingerprint_for,
)
from guardian.orchestration.checkpoint import checkpoint_path, open_checkpointer
from guardian.orchestration.remediation_graph import (
    CaseNotAwaitingDecisionError,
    CaseThreadNotResumableError,
    build_remediation_graph,
    continue_case,
    pending_cases,
    resume_case,
    start_case,
)
from guardian.storage.database import Database

T0 = datetime(2026, 1, 1, tzinfo=UTC)
ROOT = "/work/juice-shop"


class FakeServices:
    def __init__(self, verify_statuses=("VERIFIED",), apply_errors=(), pr_results=(None,)):
        self.calls: list[tuple] = []
        self.verify_statuses = list(verify_statuses)
        self.apply_errors = list(apply_errors)
        self.pr_results = list(pr_results)

    def plan(self, case_id):
        self.calls.append(("plan", case_id))

    def publish(self, case_id):
        self.calls.append(("publish", case_id))
        return "SEC-1"

    def notify(self, case_id, stage, payload):
        self.calls.append(("notify", stage, payload["attempt"]))

    def apply(self, case_id, decision):
        self.calls.append(("apply", decision))
        if self.apply_errors:
            raise self.apply_errors.pop(0)
        return {"case_id": case_id, "branch": "guardian/fix-x"}

    def validate(self, case_id, applied):
        self.calls.append(("validate", applied["branch"]))
        return {"case_id": case_id, "sandbox": "docker"}

    def verify(self, case_id, applied, validation):
        status = (
            self.verify_statuses.pop(0)
            if len(self.verify_statuses) > 1
            else self.verify_statuses[0]
        )
        self.calls.append(("verify", status))
        return {"case_id": case_id, "status": status, "reasons": [f"rescan {status}"]}

    def open_pr(self, case_id, applied, verification):
        self.calls.append(("open_pr", verification["status"]))
        result = self.pr_results.pop(0) if len(self.pr_results) > 1 else self.pr_results[0]
        if isinstance(result, BaseException):
            raise result
        return result

    def record_acceptance(self, case_id, decision):
        self.calls.append(("record_acceptance", decision.decline_reason))

    def count(self, name):
        return sum(1 for call in self.calls if call[0] == name)


def _case() -> RemediationCase:
    fp = fingerprint_for(ROOT, "pkg:npm/jsonwebtoken@0.4.0", "CVE-2015-9235")
    return RemediationCase(
        id=case_id_for(fp),
        fingerprint=fp,
        scan_id="s1",
        repository_root=ROOT,
        finding_ids=["f1"],
        title="jsonwebtoken",
        priority=Priority.P1,
        created_at=T0,
        updated_at=T0,
    )


def _seed(db: Database) -> str:
    repo_id = db.repositories.upsert(ROOT, "juice-shop")
    profile = RepositoryProfile(
        name="juice-shop",
        root=ROOT,
        profiled_at=T0,
        total_files=1,
        total_bytes=1,
        git=GitInfo(is_repository=True),
    )
    db.scans.create("s1", repo_id, T0, profile)
    return db.remediation.create(_case()).id


def _decision(case_id, kind=DecisionType.ACCEPT, **extra) -> HumanDecision:
    return HumanDecision(
        case_id=case_id,
        decision=kind,
        actor_id="acc-1",
        actor_display="Alice",
        channel="jira",
        jira_comment_id=extra.pop("comment", "10001"),
        decided_at=T0,
        **extra,
    )


class Env:
    """One 'process': a Database, a SqliteSaver and a compiled graph over files in tmp_path."""

    def __init__(self, tmp_path, services):
        self.stack = ExitStack()
        self.db = self.stack.enter_context(Database(tmp_path / "guardian.db"))
        saver = self.stack.enter_context(open_checkpointer(checkpoint_path(tmp_path / "data")))
        self.services = services
        self.graph = build_remediation_graph(self.db, services, saver)

    def status(self, case_id):
        return self.db.remediation.get(case_id).status

    def status_events(self, case_id):
        return [e.event for e in self.db.audit.list(case_id) if e.event.startswith("status:")]

    def close(self):
        self.stack.close()


@pytest.fixture
def env(tmp_path):
    environment = Env(tmp_path, FakeServices())
    yield environment
    environment.close()


@pytest.fixture
def case_id(env):
    return _seed(env.db)


def test_runs_to_interrupt_awaiting_decision(env, case_id):
    info = start_case(env.graph, case_id)
    assert info is not None
    assert info.payload["case_id"] == case_id
    assert info.payload["status"] == "AWAITING_DECISION"
    assert info.payload["jira_key"] == "SEC-1"
    assert info.payload["attempt"] == 1
    assert env.status(case_id) is CaseStatus.AWAITING_DECISION
    assert env.services.count("publish") == 1
    assert pending_cases(env.graph, [case_id, "rc_other"]) == [case_id]
    # Starting again does not re-plan or re-publish.
    assert start_case(env.graph, case_id) == info
    assert env.services.count("publish") == 1
    assert env.services.count("plan") == 1


def test_restart_durability_accept_reaches_verified_then_closed(tmp_path):
    first = Env(tmp_path, FakeServices())
    case_id = _seed(first.db)
    start_case(first.graph, case_id)
    first.close()

    services = FakeServices()
    second = Env(tmp_path, services)  # new process: new DB handle, saver and graph object
    try:
        result = resume_case(second.graph, case_id, _decision(case_id))
        assert result.finished
        assert result.interrupt is None
        assert second.status(case_id) is CaseStatus.CLOSED
        assert services.count("publish") == 0
        assert services.count("plan") == 0
        assert ("notify", "verified", 1) in services.calls
        assert second.status_events(case_id) == [
            "status:PROPOSED->AWAITING_DECISION",
            "status:AWAITING_DECISION->APPROVED",
            "status:APPROVED->APPLYING",
            "status:APPLYING->VALIDATING",
            "status:VALIDATING->VERIFIED",
            "status:VERIFIED->CLOSED",
        ]
        approved = next(e for e in second.db.audit.list(case_id) if e.event.endswith("->APPROVED"))
        assert approved.actor == "jira:acc-1"
        ok, problems = second.db.audit.verify()
        assert ok, problems
        assert pending_cases(second.graph, [case_id]) == []
    finally:
        second.close()


def test_decline_accepted_risk_closes_without_apply(env, case_id):
    start_case(env.graph, case_id)
    decline = _decision(
        case_id,
        DecisionType.DECLINE,
        decline_reason=DeclineReason.ACCEPTED_RISK,
        risk_acceptance_expires=date(2027, 1, 1),
        justification="intentional training vulnerability",
    )
    result = resume_case(env.graph, case_id, decline)
    assert result.finished
    assert env.status(case_id) is CaseStatus.CLOSED
    assert env.services.count("apply") == 0
    assert ("record_acceptance", DeclineReason.ACCEPTED_RISK) in env.services.calls
    assert ("notify", "declined", 1) in env.services.calls
    assert env.status_events(case_id)[-2:] == [
        "status:AWAITING_DECISION->DECLINED",
        "status:DECLINED->CLOSED",
    ]


def test_failed_verification_returns_to_review_then_second_accept_verifies(tmp_path):
    env = Env(tmp_path, FakeServices(verify_statuses=("FAILED", "VERIFIED")))
    try:
        case_id = _seed(env.db)
        start_case(env.graph, case_id)
        result = resume_case(env.graph, case_id, _decision(case_id))
        assert not result.finished
        assert result.interrupt is not None
        assert result.interrupt.payload["attempt"] == 2
        assert result.interrupt.payload["last_verification"] == "FAILED"
        assert env.status(case_id) is CaseStatus.AWAITING_DECISION
        assert Counter(c[:2] for c in env.services.calls if c[0] == "notify") == {
            ("notify", "failed"): 1
        }

        result = resume_case(env.graph, case_id, _decision(case_id, comment="10002"))
        assert result.finished
        assert result.values["attempt"] == 2
        assert env.status(case_id) is CaseStatus.CLOSED
        assert env.services.count("apply") == 2
        assert ("notify", "verified", 2) in env.services.calls
        assert "status:VALIDATING->VALIDATION_FAILED" in env.status_events(case_id)
        assert "status:VALIDATION_FAILED->AWAITING_DECISION" in env.status_events(case_id)
        assert env.db.audit.verify()[0]
    finally:
        env.close()


def test_revalidate_reuses_previous_decision(tmp_path):
    env = Env(tmp_path, FakeServices(verify_statuses=("UNVERIFIED", "VERIFIED")))
    try:
        case_id = _seed(env.db)
        start_case(env.graph, case_id)
        modify = _decision(case_id, DecisionType.MODIFY, modify=ModifyPayload(version="4.2.2"))
        resume_case(env.graph, case_id, modify)
        result = resume_case(
            env.graph, case_id, _decision(case_id, DecisionType.REVALIDATE, comment="10003")
        )
        assert result.finished
        applied = [c[1] for c in env.services.calls if c[0] == "apply"]
        assert applied == [modify, modify]
        assert "status:AWAITING_DECISION->APPROVED" in env.status_events(case_id)
    finally:
        env.close()


def test_modify_passes_decision_to_apply_unchanged(env, case_id):
    start_case(env.graph, case_id)
    modify = _decision(case_id, DecisionType.MODIFY, modify=ModifyPayload(version="9.0.2"))
    resume_case(env.graph, case_id, modify)
    applied = [c[1] for c in env.services.calls if c[0] == "apply"]
    assert applied == [modify]
    assert "status:AWAITING_DECISION->MODIFICATION_REQUESTED" in env.status_events(case_id)
    assert "status:MODIFICATION_REQUESTED->APPLYING" in env.status_events(case_id)


def test_invalid_resume_is_refused_and_thread_stays_interrupted(env, case_id):
    start_case(env.graph, case_id)
    with pytest.raises(ValueError, match="not"):
        resume_case(env.graph, case_id, _decision("rc_someoneelse"))

    # A raw resume with a malformed payload (bypassing resume_case) re-interrupts with an error
    # instead of poisoning the thread with a stored bad resume value.
    from langgraph.types import Command

    env.graph.invoke(
        Command(resume={"decision": "ACCEPT"}), {"configurable": {"thread_id": case_id}}
    )
    snapshot = env.graph.get_state({"configurable": {"thread_id": case_id}})
    assert snapshot.next == ("await_decision",)
    assert "error" in snapshot.interrupts[-1].value
    assert env.status(case_id) is CaseStatus.AWAITING_DECISION
    assert pending_cases(env.graph, [case_id]) == [case_id]

    # REVALIDATE without an earlier accepted decision is rejected the same way.
    env.graph.invoke(
        Command(resume=_decision(case_id, DecisionType.REVALIDATE).model_dump(mode="json")),
        {"configurable": {"thread_id": case_id}},
    )
    assert pending_cases(env.graph, [case_id]) == [case_id]
    assert env.services.count("apply") == 0

    result = resume_case(env.graph, case_id, _decision(case_id))
    assert result.finished
    assert env.status(case_id) is CaseStatus.CLOSED


def test_resume_of_non_interrupted_thread_is_refused(env, case_id):
    with pytest.raises(CaseNotAwaitingDecisionError):
        resume_case(env.graph, case_id, _decision(case_id))  # never started
    start_case(env.graph, case_id)
    resume_case(env.graph, case_id, _decision(case_id))
    with pytest.raises(CaseNotAwaitingDecisionError):
        resume_case(env.graph, case_id, _decision(case_id))  # already finished
    with pytest.raises(CaseThreadNotResumableError):
        continue_case(env.graph, case_id)


def test_crash_inside_apply_replays_without_duplicates(tmp_path):
    env = Env(tmp_path, FakeServices(apply_errors=[RuntimeError("worker died")]))
    try:
        case_id = _seed(env.db)
        start_case(env.graph, case_id)
        with pytest.raises(RuntimeError, match="worker died"):
            resume_case(env.graph, case_id, _decision(case_id))
        assert env.status(case_id) is CaseStatus.APPLYING
        with pytest.raises(CaseNotAwaitingDecisionError):
            resume_case(env.graph, case_id, _decision(case_id))

        result = continue_case(env.graph, case_id)
        assert result.finished
        assert env.status(case_id) is CaseStatus.CLOSED
        assert env.services.count("apply") == 2
        events = env.status_events(case_id)
        assert len(events) == len(set(events))
        graph_events = [e.event for e in env.db.audit.list(case_id) if e.event.startswith("graph:")]
        assert Counter(graph_events)["graph:apply"] == 1
        assert Counter(graph_events)["graph:notify:verified"] == 1
        assert env.services.count("notify") == 1
        assert env.db.audit.verify()[0]
    finally:
        env.close()


def test_domain_apply_failure_goes_back_to_review(tmp_path):
    env = Env(tmp_path, FakeServices(apply_errors=[GuardianError("patch does not apply")]))
    try:
        case_id = _seed(env.db)
        start_case(env.graph, case_id)
        result = resume_case(env.graph, case_id, _decision(case_id))
        assert result.interrupt is not None
        assert result.interrupt.payload["last_error"] == "patch does not apply"
        assert env.services.count("validate") == 0
        assert "status:APPLYING->VALIDATION_FAILED" in env.status_events(case_id)
        assert env.status(case_id) is CaseStatus.AWAITING_DECISION
        assert ("notify", "failed", 1) in env.services.calls
    finally:
        env.close()


# --- pull requests ---------------------------------------------------------------------------

PR = {"url": "https://github.com/acme/juice-shop/pull/7", "number": 7, "draft": True}


def _events(env, case_id, prefix=""):
    return [e.event for e in env.db.audit.list(case_id) if e.event.startswith(prefix)]


def test_verified_opens_the_pull_request_once_then_closes(tmp_path):
    env = Env(tmp_path, FakeServices(pr_results=[PR]))
    try:
        case_id = _seed(env.db)
        start_case(env.graph, case_id)
        result = resume_case(env.graph, case_id, _decision(case_id))
        assert result.finished
        assert result.values["pull_request"]["url"] == PR["url"]
        assert env.status(case_id) is CaseStatus.CLOSED
        assert env.services.count("open_pr") == 1
        assert ("notify", "pr_opened", 1) in env.services.calls
        events = _events(env, case_id)
        assert events.count("pr:opened") == 1
        # The pull request is opened before the case is closed and reported back.
        assert events.index("pr:opened") < events.index("status:VERIFIED->CLOSED")
        opened = next(e for e in env.db.audit.list(case_id) if e.event == "pr:opened")
        assert '"number":7' in opened.payload_json
        assert env.db.audit.verify()[0]
    finally:
        env.close()


class CrashAfterPr(FakeServices):
    """Opens the pull request, then crashes in the next node (report_back's notify)."""

    def __init__(self):
        super().__init__(pr_results=[PR])
        self.crashed = False

    def notify(self, case_id, stage, payload):
        if stage == "verified" and not self.crashed:
            self.crashed = True
            raise RuntimeError("process died")
        super().notify(case_id, stage, payload)


def test_crash_retry_and_replay_never_open_twice(tmp_path):
    env = Env(tmp_path, CrashAfterPr())
    try:
        case_id = _seed(env.db)
        start_case(env.graph, case_id)
        with pytest.raises(RuntimeError, match="process died"):
            resume_case(env.graph, case_id, _decision(case_id))
        assert env.status(case_id) is CaseStatus.VERIFIED
        result = continue_case(env.graph, case_id)
        assert result.finished
        assert env.services.count("open_pr") == 1
        assert _events(env, case_id).count("pr:opened") == 1

        # A replay of the node itself (crash after its audit, before its checkpoint).
        from guardian.orchestration.remediation_graph import _Nodes

        nodes = _Nodes(env.db, env.services)
        state = {"case_id": case_id, "attempt": 1, "applied": {}, "verification": {}}
        assert nodes.open_pr(state)["pull_request"]["url"] == PR["url"]
        assert env.services.count("open_pr") == 1
        assert Counter(_events(env, case_id, "graph:"))["graph:notify:pr_opened"] == 1
    finally:
        env.close()


def test_pull_requests_disabled_are_skipped_silently(env, case_id):
    start_case(env.graph, case_id)
    result = resume_case(env.graph, case_id, _decision(case_id))
    assert result.finished
    assert env.services.count("open_pr") == 1  # asked; the service said "disabled"
    assert result.values["pull_request"] is None
    assert not _events(env, case_id, "pr:")
    assert "graph:open_pr" not in _events(env, case_id)
    assert env.status(case_id) is CaseStatus.CLOSED


def test_pr_failure_is_audited_and_the_case_still_closes(tmp_path):
    env = Env(tmp_path, FakeServices(pr_results=[GuardianError("git push rejected")]))
    try:
        case_id = _seed(env.db)
        start_case(env.graph, case_id)
        result = resume_case(env.graph, case_id, _decision(case_id))
        assert result.finished
        assert result.values["last_event"] == "closed"
        assert env.status(case_id) is CaseStatus.CLOSED
        assert "status:VERIFIED->CLOSED" in env.status_events(case_id)
        failed = [e for e in env.db.audit.list(case_id) if e.event == "pr:failed"]
        assert len(failed) == 1
        assert "git push rejected" in failed[0].payload_json
        assert ("notify", "pr_failed", 1) in env.services.calls
        assert ("notify", "verified", 1) in env.services.calls

        from guardian.orchestration.remediation_graph import _Nodes

        replay = _Nodes(env.db, env.services).open_pr({"case_id": case_id, "attempt": 1})
        assert replay["last_event"] == "pr_failed"
        assert env.services.count("open_pr") == 1
        assert _events(env, case_id).count("pr:failed") == 1
    finally:
        env.close()


def test_failed_verdict_never_opens_a_pull_request(tmp_path):
    env = Env(tmp_path, FakeServices(verify_statuses=("FAILED",), pr_results=[PR]))
    try:
        case_id = _seed(env.db)
        start_case(env.graph, case_id)
        result = resume_case(env.graph, case_id, _decision(case_id))
        assert result.interrupt is not None
        assert env.services.count("open_pr") == 0
        assert not _events(env, case_id, "pr:")
    finally:
        env.close()


def test_decline_never_opens_a_pull_request(env, case_id):
    start_case(env.graph, case_id)
    decline = _decision(
        case_id, DecisionType.DECLINE, decline_reason=DeclineReason.WONT_FIX, comment="10009"
    )
    assert resume_case(env.graph, case_id, decline).finished
    assert env.services.count("open_pr") == 0


def test_thread_paused_by_the_previous_graph_shape_resumes(tmp_path):
    """A thread created (and paused at await_decision) by the graph without open_pr resumes
    under the current graph and runs the new node."""
    from langgraph.graph import END, START, StateGraph

    from guardian.orchestration import remediation_graph as rg
    from guardian.orchestration.state import RemediationState

    services = FakeServices(pr_results=[PR])
    with Database(tmp_path / "guardian.db") as db:
        case_id = _seed(db)
        with open_checkpointer(checkpoint_path(tmp_path / "data")) as saver:
            nodes = rg._Nodes(db, services)
            old = StateGraph(RemediationState)
            for name in (
                "plan",
                "publish_jira",
                "await_decision",
                "apply",
                "validate",
                "rescan_verify",
                "publish_failure",
                "record_acceptance",
                "report_back",
            ):
                old.add_node(name, getattr(nodes, name))
            old.add_edge(START, "plan")
            old.add_edge("plan", "publish_jira")
            old.add_edge("publish_jira", "await_decision")
            old.add_conditional_edges(
                "await_decision", rg._after_decision, ["apply", "record_acceptance"]
            )
            old.add_conditional_edges("apply", rg._after_apply, ["validate", "publish_failure"])
            old.add_conditional_edges(
                "validate", rg._after_validate, ["rescan_verify", "publish_failure"]
            )
            old.add_conditional_edges(
                "rescan_verify",
                lambda s: "report_back" if s.get("last_event") == "verified" else "publish_failure",
                ["report_back", "publish_failure"],
            )
            old.add_edge("publish_failure", "await_decision")
            old.add_edge("record_acceptance", "report_back")
            old.add_edge("report_back", END)
            assert start_case(old.compile(checkpointer=saver), case_id) is not None

        with open_checkpointer(checkpoint_path(tmp_path / "data")) as saver:
            graph = build_remediation_graph(db, services, saver)
            assert pending_cases(graph, [case_id]) == [case_id]
            result = resume_case(graph, case_id, _decision(case_id))
        assert result.finished
        assert services.count("open_pr") == 1
        assert db.remediation.get(case_id).status is CaseStatus.CLOSED

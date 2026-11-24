"""End to end, offline: scan -> remediate -> human decision -> graph -> apply -> validate -> rescan.

Real pieces: the Typer CLI, SQLite storage and audit chain, the LangGraph remediation graph with
its SqliteSaver checkpoints, ``GuardianServices``, ``apply_case`` (real git worktree on a
``guardian/fix-*`` branch, real package.json edit), ``validate_case`` and ``verify_case``.
Fakes: the Docker sandbox, the rescan (``scan_fn``), the npm registry and Jira.
"""

import itertools
import json
import threading
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from jira_fake import APPROVER_ID, BASE_URL, EMAIL, TOKEN, FakeJira
from juice_shop import PACKAGE_JSON, FakeRegistry, seed_scan
from remediation_fakes import DEFAULT_TOOL_RUNS, FakeSandbox, git, profile_for
from typer.testing import CliRunner

from guardian.cli import common
from guardian.cli import decide as decide_module
from guardian.cli import jira as jira_cli
from guardian.cli import remediate as remediate_module
from guardian.cli.main import app
from guardian.core.config import GuardianSettings
from guardian.core.models import ScanStatus
from guardian.core.remediation_models import (
    CaseStatus,
    DecisionType,
    HumanDecision,
    StepStatus,
)
from guardian.orchestration.checkpoint import checkpoint_path
from guardian.remediation import runtime
from guardian.remediation.sandbox import StepResult
from guardian.storage.database import Database
from guardian.ui import decisions as ui_decisions
from guardian.ui.server import ConsoleApp, make_server

cli = CliRunner()
SCAN_ID = "scan-juice-1"
ORIGINAL_DEPS = json.loads(PACKAGE_JSON)["dependencies"]
TEST_OUTPUT = "# tests 3\n# pass 3\n# fail 0\n"  # node --test TAP summary


class FakeRescan:
    """``scan_fn`` factory: stores an "after" scan of the worktree. With ``resolve`` on, the
    findings of every package whose package.json entry changed are gone."""

    def __init__(self) -> None:
        self.resolve = True
        self.paths: list[Path] = []
        self._ids = itertools.count(1)

    def bind(self, db: Database):
        def scan(path: Path) -> str:
            self.paths.append(path)
            deps = json.loads((path / "package.json").read_text())["dependencies"]
            changed = {name for name, spec in deps.items() if ORIGINAL_DEPS.get(name) != spec}
            kept = [
                f
                for f in db.findings.load(SCAN_ID)
                if not (self.resolve and f.details.package in changed)
            ]
            scan_id = f"after-{next(self._ids)}"
            now = datetime.now(UTC)
            repo_id = db.repositories.upsert(str(path), "juice-shop")
            db.scans.create(scan_id, repo_id, now, profile_for(str(path)))
            sbom = db.sboms.load(SCAN_ID)
            db.sboms.save(scan_id, sbom)
            db.findings.save(scan_id, kept, [])
            db.scans.finish(
                scan_id,
                status=ScanStatus.COMPLETED,
                finished_at=now,
                tool_runs=list(DEFAULT_TOOL_RUNS),
                warnings=[],
                component_count=len(sbom.components),
                finding_count=len(kept),
            )
            return scan_id

        return scan


@pytest.fixture
def demo(monkeypatch, tmp_path):
    """A Juice Shop-shaped git repository with a stored scan, wired to fake externals."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    for name, value in {
        "GUARDIAN_DATA_DIR": str(tmp_path / "data"),
        "GUARDIAN_AI_ENABLED": "false",
        "GUARDIAN_CLI_APPROVERS": "alice",
        "GUARDIAN_APPROVERS": APPROVER_ID,
    }.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(common.console, "width", 250)
    monkeypatch.setattr(decide_module.getpass, "getuser", lambda: "alice")
    monkeypatch.setattr(ui_decisions.getpass, "getuser", lambda: "alice")
    monkeypatch.setattr(remediate_module, "build_registry", lambda settings: FakeRegistry())

    root = tmp_path / "juice-shop"
    root.mkdir()
    manifest = json.loads(PACKAGE_JSON)
    manifest["scripts"] = {
        "build:server": "tsc",
        "test:server": "node --test",
        "postinstall": "exit 1",
    }
    (root / "package.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    git(root, "init", "-q", "-b", "main")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "initial")

    settings = GuardianSettings()
    with Database(settings.database_path) as db:
        seed_scan(db, root, SCAN_ID)

    rescan = FakeRescan()
    sandbox = FakeSandbox(results={"test": StepResult(StepStatus.PASSED, 0, output=TEST_OUTPUT)})
    fake_jira = FakeJira()

    def build(db, settings, *, jira_enabled=True):
        return runtime.GuardianServices(
            db,
            settings,
            jira_enabled=jira_enabled,
            sandbox=sandbox,
            scan_fn=rescan.bind(db),
            registry=FakeRegistry(),
            jira_factory=lambda s: fake_jira.client(),
        )

    monkeypatch.setattr(runtime, "build_services", build)
    monkeypatch.setattr(jira_cli, "make_client", lambda s: fake_jira.client())
    return root, rescan, sandbox, fake_jira


def _settings() -> GuardianSettings:
    return GuardianSettings()


def _remediate(*extra: str) -> list:
    result = cli.invoke(app, ["remediate", "latest", "--no-ai", *extra])
    assert result.exit_code == 0, result.output
    with Database(_settings().database_path) as db:
        return db.remediation.list()


def _case_for(cases, package: str):
    return next(c for c in cases if c.title.startswith(f"{package} "))


def _events(case_id: str) -> list[str]:
    with Database(_settings().database_path) as db:
        return [e.event for e in db.audit.list(case_id)]


def _status(case_id: str) -> CaseStatus:
    with Database(_settings().database_path) as db:
        return db.remediation.get(case_id).status


def _verified_case(cases):
    """A case whose recommended fix is a direct upgrade (the demo's VERIFIED case)."""
    with Database(_settings().database_path) as db:
        for case in cases:
            plan = db.remediation.plan(case.id)
            chosen = {c.id: c for c in db.remediation.candidates(case.id)}.get(
                plan.chosen_candidate_id
            )
            if chosen and chosen.to_version and chosen.strategy in {None, "direct"}:
                return case
    pytest.fail("no case with a direct upgrade")


def test_scan_remediate_accept_verified_and_closed(demo):
    root, rescan, sandbox, _ = demo
    cases = _remediate("--no-jira")
    assert cases
    assert all(c.status is CaseStatus.AWAITING_DECISION for c in cases)
    target = _verified_case(cases)
    events = _events(target.id)
    assert "graph:plan" in events
    assert "graph:publish_jira" in events  # ran, published nothing (--no-jira)

    result = cli.invoke(app, ["decide", target.id, "accept"])
    assert result.exit_code == 0, result.output
    assert "Verdict: VERIFIED" in result.output
    assert "now CLOSED" in result.output
    assert _status(target.id) is CaseStatus.CLOSED

    events = _events(target.id)
    for expected in (
        "decision:recorded",
        "status:AWAITING_DECISION->APPROVED",
        "apply:committed",
        "validation:finished",
        "verify:finished",
        "status:VALIDATING->VERIFIED",
        "status:VERIFIED->CLOSED",
    ):
        assert expected in events, expected
    # The fix lives on Guardian's branch, never in the user's working tree.
    assert git(root, "branch", "--list", f"guardian/fix-{target.id}")
    assert json.loads((root / "package.json").read_text())["dependencies"] == ORIGINAL_DEPS
    assert rescan.paths == [_settings().data_dir / "worktrees" / target.id]
    assert [r["command"] for r in sandbox.runs][-2:] == [
        ["npm", "run", "build:server"],
        ["npm", "run", "test:server"],
    ]

    detail = cli.invoke(app, ["case", target.id])
    assert detail.exit_code == 0, detail.output
    assert "Validation runs" in detail.stdout
    assert "build: passed exit 0" in detail.stdout
    assert "tests 3/3 passed" in detail.stdout
    assert "VERIFIED (confidence" in detail.stdout

    audit = cli.invoke(app, ["audit", "verify"])
    assert audit.exit_code == 0, audit.output
    assert "hash chain intact" in audit.stdout


def test_decline_accepted_risk_closes_without_change(demo):
    root, rescan, _, _ = demo
    case = _case_for(_remediate("--no-jira"), "jsonwebtoken")
    result = cli.invoke(
        app,
        [
            "decide",
            case.id,
            "decline",
            "reason=accepted_risk",
            "until=2099-01-01",
            "--",
            "intentional",
            "training",
            "vuln",
        ],
    )
    assert result.exit_code == 0, result.output
    assert _status(case.id) is CaseStatus.CLOSED
    with Database(_settings().database_path) as db:
        (declined,) = [e for e in db.audit.list(case.id) if e.event == "decline:recorded"]
    payload = json.loads(declined.payload_json)
    assert payload["decline_reason"] == "ACCEPTED_RISK"
    assert payload["risk_acceptance_expires"] == "2099-01-01"
    assert "apply:started" not in _events(case.id)
    assert not rescan.paths
    assert not git(root, "branch", "--list", "guardian/*")


def test_failed_verification_returns_to_review_then_revalidate(demo):
    _, rescan, _, _ = demo
    target = _verified_case(_remediate("--no-jira"))
    rescan.resolve = False  # the rescan still finds the targets -> FAILED

    result = cli.invoke(app, ["decide", target.id, "accept"])
    assert result.exit_code == 0, result.output
    assert "Verdict: FAILED" in result.output
    assert "Returned to review" in result.output
    assert _status(target.id) is CaseStatus.AWAITING_DECISION
    assert "status:VALIDATION_FAILED->AWAITING_DECISION" in _events(target.id)

    rescan.resolve = True
    again = cli.invoke(app, ["validate", target.id])
    assert again.exit_code == 0, again.output
    assert "Verdict: VERIFIED" in again.output
    assert _status(target.id) is CaseStatus.CLOSED
    with Database(_settings().database_path) as db:
        decisions = [d.decision for d in db.remediation.decisions(target.id)]
        assert decisions == [DecisionType.ACCEPT, DecisionType.REVALIDATE]
        assert db.audit.verify() == (True, [])


def test_revalidate_without_an_attempt_is_refused(demo):
    target = _verified_case(_remediate("--no-jira"))
    result = cli.invoke(app, ["validate", target.id])
    assert result.exit_code == 2
    assert "decision ignored" in result.output


def test_restart_durability_through_the_runtime(demo):
    _, rescan, _, _ = demo
    target = _verified_case(_remediate("--no-jira"))
    settings = _settings()
    assert checkpoint_path(settings.data_dir).is_file()

    def decision(kind: DecisionType) -> HumanDecision:
        return HumanDecision(
            case_id=target.id,
            decision=kind,
            actor_id="alice",
            actor_display="alice",
            channel="cli",
            decided_at=datetime.now(UTC),
        )

    rescan.resolve = False
    first = runtime.submit_decision(settings, target.id, decision(DecisionType.ACCEPT))
    assert first.interrupt is not None
    assert first.values["attempt"] == 2

    # A fresh runtime (new connections, new graph) picks the paused thread up.
    with runtime.open_runtime(settings) as (_, graph):
        assert runtime.thread_exists(graph, target.id)
        assert not runtime.has_crashed_step(graph, target.id)
    restarted = runtime.start_cases(settings, [target.id], jira_enabled=False)
    assert restarted[0].interrupt is not None  # not restarted, same interrupt
    assert "graph:plan" in _events(target.id)
    assert _events(target.id).count("graph:plan") == 1

    rescan.resolve = True
    second = runtime.submit_decision(settings, target.id, decision(DecisionType.REVALIDATE))
    assert second.finished
    assert second.values["verification"]["status"] == "VERIFIED"
    assert _status(target.id) is CaseStatus.CLOSED

    with pytest.raises(runtime.DecisionNotApplicableError):
        runtime.submit_decision(settings, target.id, decision(DecisionType.ACCEPT))
    with pytest.raises(ValueError, match="not"):
        runtime.submit_decision(settings, "rc_other", decision(DecisionType.ACCEPT))


def test_submit_starts_a_missing_thread_and_refuses_bad_revalidate(demo):
    target = _verified_case(_remediate("--no-jira"))
    settings = _settings()
    checkpoint_path(settings.data_dir).unlink()  # e.g. a case created before the graph existed
    decision = HumanDecision(
        case_id=target.id,
        decision=DecisionType.REVALIDATE,
        actor_id="alice",
        actor_display="alice",
        channel="cli",
        decided_at=datetime.now(UTC),
    )
    with pytest.raises(runtime.DecisionNotApplicableError, match="no earlier"):
        runtime.submit_decision(settings, target.id, decision)
    with runtime.open_runtime(settings) as (db, graph):
        assert runtime.thread_exists(graph, target.id)
        assert not db.remediation.decisions(target.id)  # nothing recorded


def test_jira_publish_sync_and_writeback(demo, monkeypatch):
    _, _, _, fake = demo
    for name, value in {
        "JIRA_BASE_URL": BASE_URL,
        "JIRA_EMAIL": EMAIL,
        "JIRA_API_TOKEN": TOKEN,
        "JIRA_PROJECT_KEY": "SEC",
    }.items():
        monkeypatch.setenv(name, value)
    cases = _remediate()
    target = _verified_case(cases)
    target = next(c for c in _all_cases() if c.id == target.id)
    assert target.jira_key, "remediate publishes open cases to Jira"
    assert len(fake.issues) == len(cases)

    fake.add_comment(target.jira_key, APPROVER_ID, "/guardian accept")
    result = cli.invoke(app, ["jira", "sync"])
    assert result.exit_code == 0, result.output
    assert "resuming the remediation graph" in result.output
    assert _status(target.id) is CaseStatus.CLOSED
    replies = "\n".join(fake.guardian_replies(target.jira_key))
    assert "Decision acknowledged" in replies
    assert "Applying the approved change" in replies
    assert "Validation results" in replies
    assert "Verification verdict" in replies
    with Database(_settings().database_path) as db:
        assert len(db.remediation.decisions(target.id)) == 1
        assert db.audit.verify() == (True, [])

    # A second sync sees nothing new and posts nothing.
    before = len(fake.guardian_replies(target.jira_key))
    assert cli.invoke(app, ["jira", "sync"]).exit_code == 0
    assert len(fake.guardian_replies(target.jira_key)) == before


def test_jira_outage_does_not_block_remediation(demo, monkeypatch):
    _, _, _, fake = demo
    for name, value in {
        "JIRA_BASE_URL": BASE_URL,
        "JIRA_EMAIL": EMAIL,
        "JIRA_API_TOKEN": TOKEN,
        "JIRA_PROJECT_KEY": "SEC",
    }.items():
        monkeypatch.setenv(name, value)
    fake.queued = [httpx.Response(401)] * 50
    cases = _remediate()
    assert all(c.jira_key is None for c in _all_cases())
    target = _verified_case(cases)
    assert "jira:publish_failed" in _events(target.id)
    result = cli.invoke(app, ["decide", target.id, "accept"])
    assert result.exit_code == 0, result.output
    assert _status(target.id) is CaseStatus.CLOSED


def _all_cases():
    with Database(_settings().database_path) as db:
        return db.remediation.list()


def test_web_ui_decision_runs_the_graph(demo):
    target = _verified_case(_remediate("--no-jira"))
    settings = _settings()
    console_app = ConsoleApp(settings, port=0, handler=runtime.make_ui_decision_handler(settings))
    server = make_server(console_app, 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{console_app.port}"
    headers = {"X-Guardian-Token": console_app.token, "Origin": base}
    try:
        with httpx.Client(base_url=base, timeout=10) as client:
            response = client.post(
                f"/api/cases/{target.id}/decision", headers=headers, json={"action": "accept"}
            )
            assert response.status_code == 202, response.text
            for worker in console_app.decisions.threads:
                worker.join(timeout=60)
            detail = client.get(f"/api/cases/{target.id}", headers=headers).json()
    finally:
        server.shutdown()
        server.server_close()
    assert detail["case"]["status"] == "CLOSED"
    events = _events(target.id)
    assert events.count("decision:recorded") == 1  # the UI recorded it; the graph did not
    assert "decision:handler_failed" not in events
    assert "status:VALIDATING->VERIFIED" in events


def test_remediate_latest_skips_verification_rescans(demo):
    target = _verified_case(_remediate("--no-jira"))
    assert cli.invoke(app, ["decide", target.id, "accept"]).exit_code == 0
    with Database(_settings().database_path) as db:
        assert db.scans.resolve("latest").startswith("after-")  # the worktree rescan
        assert remediate_module.resolve_scan(db, _settings(), "latest") == SCAN_ID
        assert remediate_module.resolve_scan(db, _settings(), SCAN_ID[:8]) == SCAN_ID
    again = cli.invoke(app, ["remediate", "latest", "--no-ai", "--no-jira"])
    assert again.exit_code == 0, again.output
    assert "after-" not in again.output
    with Database(_settings().database_path) as db:
        assert {c.scan_id for c in db.remediation.list()} == {SCAN_ID}

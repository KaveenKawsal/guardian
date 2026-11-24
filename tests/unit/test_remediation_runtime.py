"""The remediation runtime: real services' edge cases, crash recovery and the CLI around them."""

import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
import typer
from jira_fake import FakeJira, jira_settings, seed_case, seed_scan
from remediation_fakes import FakeSandbox, StubServices, stub_runtime
from typer.testing import CliRunner

from guardian.cli import decide as decide_module
from guardian.cli import doctor as doctor_module
from guardian.cli import scan as scan_cli
from guardian.cli.main import app
from guardian.core.config import GuardianSettings
from guardian.core.models import Priority
from guardian.core.remediation_models import (
    CaseStatus,
    DecisionType,
    DeclineReason,
    HumanDecision,
    StepStatus,
)
from guardian.orchestration.remediation_graph import CaseNotAwaitingDecisionError
from guardian.remediation import runtime
from guardian.remediation.apply import AppliedChange, RemediationApplyError
from guardian.remediation.sandbox import StepResult
from guardian.storage.audit import AuditStore
from guardian.storage.database import Database

cli = CliRunner()


@pytest.fixture
def settings(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GUARDIAN_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("GUARDIAN_CLI_APPROVERS", "alice")
    monkeypatch.setattr(decide_module, "current_user", lambda: "alice")
    value = jira_settings(tmp_path)
    with Database(value.database_path) as db:
        seed_scan(db)
    return value


def _decision(case_id, kind=DecisionType.ACCEPT, **extra) -> HumanDecision:
    return HumanDecision(
        case_id=case_id,
        decision=kind,
        actor_id="alice",
        actor_display="alice",
        channel="cli",
        decided_at=datetime.now(UTC),
        **extra,
    )


# --- helpers ---------------------------------------------------------------------------


def test_settings_map_onto_the_sandbox(settings):
    tuned = settings.model_copy(
        update={
            "sandbox_cpus": "4",
            "sandbox_memory": "8g",
            "sandbox_timeout_seconds": 60.0,
            "npm_lockfile_generation": True,
        }
    )
    config = runtime.sandbox_config(tuned)
    assert (config.cpus, config.memory, config.step_timeout_seconds) == ("4", "8g", 60.0)
    assert runtime.docker_sandbox(tuned).config.install_timeout_seconds == 60.0
    assert runtime.lockfile_generator_for(tuned, FakeSandbox()) is not None
    off = tuned.model_copy(update={"npm_lockfile_generation": False})
    assert runtime.lockfile_generator_for(off, FakeSandbox()) is None
    assert runtime.default_registry(tuned) is not None


def test_applied_change_round_trip(tmp_path):
    applied = AppliedChange("rc_1", "guardian/fix-rc_1", tmp_path, "abc", "def", ["package.json"])
    assert runtime.applied_from_json(runtime.applied_to_json(applied)) == applied
    with pytest.raises(RemediationApplyError, match="boom"):
        runtime.applied_from_json({"error": "boom"})


# --- services --------------------------------------------------------------------------


def _services(db, settings, fake=None, **kwargs):
    fake = fake or FakeJira()
    return runtime.GuardianServices(
        db, settings, sandbox=FakeSandbox(), jira_factory=lambda s: fake.client(), **kwargs
    )


def test_apply_without_repository_is_a_domain_failure(settings):
    with Database(settings.database_path) as db:
        case = seed_case(db)[0]
        services = _services(db, settings)
        with pytest.raises(RemediationApplyError, match="not available"):
            services.apply(case.id, _decision(case.id))


def test_apply_and_validate_wrap_os_errors(settings, tmp_path, monkeypatch):
    with Database(settings.database_path) as db:
        case = seed_case(db)[0]
        services = _services(db, settings)
        monkeypatch.setattr(Path, "is_dir", lambda self: True)

        def broken(*args, **kwargs):
            msg = "denied"
            raise PermissionError(msg)

        monkeypatch.setattr(runtime, "apply_case", broken)
        with pytest.raises(RemediationApplyError, match="worktree"):
            services.apply(case.id, _decision(case.id))
        monkeypatch.setattr(runtime, "validate_case", broken)
        applied = runtime.applied_to_json(AppliedChange(case.id, "b", tmp_path, "c", "d"))
        with pytest.raises(runtime.RemediationValidationError, match="denied"):
            services.validate(case.id, applied)


def test_publish_respects_priority_floor_and_disabled_jira(settings):
    with Database(settings.database_path) as db:
        low = seed_case(db, package="low", priority=Priority.P4)[0]
        assert _services(db, settings).publish(low.id) is None
        off = runtime.GuardianServices(db, settings, jira_enabled=False, sandbox=FakeSandbox())
        assert off.publish(low.id) is None
        off.notify(low.id, "failed", {"attempt": 1})  # no-op without Jira


def test_notify_posts_each_stage_once_and_survives_jira_errors(settings):
    fake = FakeJira()
    with Database(settings.database_path) as db:
        case = seed_case(db)[0]
        services = _services(db, settings, fake)
        services.notify(case.id, "failed", {"attempt": 1})  # no link yet: nothing posted
        key = fake.add_issue(["guardian"])
        db.remediation.link_jira(case.id, key)
        services.notify(case.id, "failed", {"attempt": 1, "error": "tests failed"})
        services.notify(case.id, "failed", {"attempt": 1, "error": "tests failed"})
        services.notify(case.id, "verified", {"attempt": 2})
        services.notify(case.id, "declined", {"attempt": 3, "decline_reason": "WONT_FIX"})
        services.notify(case.id, "unknown", {"attempt": 4})
        replies = fake.guardian_replies(key)
        assert len(replies) == 3
        assert "Validation failed: tests failed" in replies[0]
        assert "Verified." in replies[1]
        assert "Declined: WONT_FIX" in replies[2]

        fake.queued = [httpx.Response(400, json={"errorMessages": ["nope"]})]
        services.notify(case.id, "failed", {"attempt": 9})
        assert "jira:comment_failed" in [e.event for e in db.audit.list(case.id)]
        services.close()
        services.close()


def test_record_acceptance_is_idempotent(settings):
    with Database(settings.database_path) as db:
        case = seed_case(db)[0]
        services = _services(db, settings)
        decision = _decision(
            case.id,
            DecisionType.DECLINE,
            decline_reason=DeclineReason.WONT_FIX,
            justification="not worth it",
        )
        services.record_acceptance(case.id, decision)
        services.record_acceptance(case.id, decision)
        events = [e for e in db.audit.list(case.id) if e.event == runtime.DECLINE_EVENT]
        assert len(events) == 1
        assert services.scan_fn is services.scan_fn  # built once, lazily


def test_plan_rebuilds_missing_candidates(settings, monkeypatch):
    calls = []
    monkeypatch.setattr(runtime, "create_cases", lambda *a, **kw: calls.append(kw))
    with Database(settings.database_path) as db:
        case = seed_case(db)[0]
        services = _services(db, settings, registry=object())
        services.plan(case.id)  # plan and candidates present: no-op
        assert calls == []
        db.remediation.replace_candidates(case.id, [])
        services.plan(case.id)
    assert calls[0]["finding_ids"] == case.finding_ids
    assert calls[0]["no_ai"] is True


def test_replace_candidates_drops_stale_ids_with_audit(settings):
    with Database(settings.database_path) as db:
        case, _, _, candidates, _ = seed_case(db)
        removed = db.remediation.replace_candidates(case.id, candidates[:1])
        assert removed == [candidates[1].id]
        assert [c.id for c in db.remediation.candidates(case.id)] == [candidates[0].id]
        assert db.remediation.replace_candidates(case.id, candidates[:1]) == []
        events = [e.event for e in db.audit.list(case.id)]
        assert events.count("candidates:removed") == 1
        refreshed = db.remediation.refresh_case(case.id, "scan-1", ["f-new"])
        assert refreshed.finding_ids == ["f-new"]
        assert db.audit.verify() == (True, [])


# --- runtime: crashes, retries, start errors -----------------------------------------------


class CrashingServices(StubServices):
    def __init__(self):
        super().__init__()
        self.crash = True

    def apply(self, case_id, decision):
        if self.crash:
            msg = "disk on fire"
            raise RuntimeError(msg)
        return super().apply(case_id, decision)


def test_crash_then_validate_retries_the_pending_step(settings, monkeypatch):
    services = stub_runtime(monkeypatch, CrashingServices())
    with Database(settings.database_path) as db:
        case = seed_case(db)[0]
    with pytest.raises(RuntimeError, match="disk on fire"):
        runtime.submit_decision(settings, case.id, _decision(case.id))
    assert runtime.case_has_crashed_step(settings, case.id)
    with Database(settings.database_path) as db:
        db.remediation.get(case.id)  # still readable

    # The case status moved to APPLYING inside the crashed node, so a new decision is refused.
    with pytest.raises(runtime.DecisionNotApplicableError):
        runtime.submit_decision(settings, case.id, _decision(case.id))

    services.crash = False
    result = cli.invoke(app, ["validate", case.id])
    assert result.exit_code == 0, result.output
    assert "Retrying the interrupted step" in result.output
    assert "Case closed." in result.output
    assert not runtime.case_has_crashed_step(settings, case.id)


def test_submit_refuses_a_thread_that_is_not_paused(settings, monkeypatch):
    stub_runtime(monkeypatch)
    with Database(settings.database_path) as db:
        case = seed_case(db)[0]
    monkeypatch.setattr(runtime, "is_awaiting_decision", lambda graph, case_id: False)
    with pytest.raises(CaseNotAwaitingDecisionError, match="not paused"):
        runtime.submit_decision(settings, case.id, _decision(case.id))


def test_start_cases_reports_per_case_errors(settings, monkeypatch):
    class Broken(StubServices):
        def plan(self, case_id):
            msg = "planner down"
            raise RuntimeError(msg)

    stub_runtime(monkeypatch, Broken())
    with Database(settings.database_path) as db:
        case = seed_case(db)[0]
        closed = seed_case(db, package="done", status=CaseStatus.CLOSED)[0]
    results = runtime.start_cases(settings, [case.id, closed.id])
    assert [(r.case_id, r.error) for r in results] == [(case.id, "RuntimeError: planner down")]


# --- CLI: audit, doctor, scan hook -------------------------------------------------------


def test_audit_verify_reports_problems(settings, monkeypatch):
    assert cli.invoke(app, ["audit", "verify"]).exit_code == 0
    monkeypatch.setattr(AuditStore, "verify", lambda self: (False, ["event 1: chain broken"]))
    result = cli.invoke(app, ["audit", "verify"])
    assert result.exit_code == 1
    assert "chain broken" in result.output


class _Sandbox:
    def __init__(self, ok=True, image=True):
        self.ok, self.image = ok, image
        self.config = runtime.SandboxConfig()

    def available(self):
        return (self.ok, "docker 28" if self.ok else "docker daemon not reachable")

    def image_exists(self, tag):
        return self.image


@pytest.mark.parametrize(
    ("sandbox", "expected"),
    [
        (_Sandbox(ok=False), "Start Docker Desktop"),
        (_Sandbox(image=False), "docker pull node:24-bookworm-slim"),
        (_Sandbox(), "node:24-bookworm-slim present"),
    ],
)
def test_doctor_docker_states(settings, monkeypatch, sandbox, expected):
    monkeypatch.setattr(doctor_module, "docker_sandbox", lambda s: sandbox)
    monkeypatch.setattr(doctor_module.console, "width", 300)
    monkeypatch.setattr(doctor_module, "TOOLS", {})
    result = cli.invoke(app, ["doctor"])
    assert result.exit_code == 0, result.output
    assert expected in result.output


def test_doctor_jira_online_and_checkpoint_failure(settings, monkeypatch):
    fake = FakeJira()
    monkeypatch.setattr(doctor_module, "docker_sandbox", lambda s: _Sandbox())
    monkeypatch.setattr(doctor_module.console, "width", 300)
    monkeypatch.setattr(doctor_module, "TOOLS", {})
    for name, value in {
        "JIRA_BASE_URL": "https://example.atlassian.net",
        "JIRA_EMAIL": "bot@example.com",
        "JIRA_API_TOKEN": "tok",
        "JIRA_PROJECT_KEY": "SEC",
    }.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(doctor_module, "jira_client_from_settings", lambda s: fake.client())
    offline = cli.invoke(app, ["doctor"])
    assert "--online to authenticate" in offline.output
    online = cli.invoke(app, ["doctor", "--online"])
    assert "authenticated as" in online.output
    fake.queued = [httpx.Response(401)]
    failed = cli.invoke(app, ["doctor", "--online"])
    assert "failed" in failed.output

    def broken(path):
        msg = "read-only"
        raise PermissionError(msg)

    monkeypatch.setattr(doctor_module, "open_checkpointer", broken)
    result = cli.invoke(app, ["doctor"])
    assert "read-only" in result.output
    monkeypatch.setenv("GUARDIAN_LLM_TEMPERATURE", "99")
    assert "invalid configuration" in cli.invoke(app, ["doctor"]).output


def test_scan_lockfile_hook(tmp_path, monkeypatch):
    printed = []

    class Progress:
        def print(self, text):
            printed.append(text)

    settings = GuardianSettings(_env_file=None, data_dir=tmp_path, npm_lockfile_generation=True)
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr(scan_cli, "docker_sandbox", lambda s: _Sandbox(ok=False))
    assert scan_cli.npm_lockfile_generator(repo, settings, Progress()) is None  # no package.json
    (repo / "package.json").write_text("{}")
    assert scan_cli.npm_lockfile_generator(repo, settings, Progress()) is None
    assert "start Docker Desktop to generate a lockfile" in printed[-1]
    monkeypatch.setattr(scan_cli, "docker_sandbox", lambda s: _Sandbox())
    assert scan_cli.npm_lockfile_generator(repo, settings, Progress()) is not None
    (repo / "package-lock.json").write_text("{}")
    assert scan_cli.npm_lockfile_generator(repo, settings, Progress()) is None
    off = settings.model_copy(update={"npm_lockfile_generation": False})
    assert scan_cli.npm_lockfile_generator(repo, off, Progress()) is None


def test_ui_hook_is_registered():
    assert isinstance(app, typer.Typer)
    names = {c.name or c.callback.__name__ for c in app.registered_commands}
    assert {"decide", "validate", "ui"} <= names


# --- npm lockfile failures carry their cause (live-run regression) ----------------------


def test_lockfile_failure_names_exit_code_and_output_tail(tmp_path):
    from guardian.remediation.lockfile import generate_npm_lockfile

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text('{"name": "x"}')
    noise = "\n".join(f"npm http fetch GET 200 line {i}" for i in range(40))
    output = f"{noise}\nnpm ERR! code E401\nnpm ERR! token=ghp_{'a' * 36}\n"
    sandbox = FakeSandbox(
        results={"lockfile": StepResult(StepStatus.FAILED, 1, 3.0, output)}, lockfile=None
    )
    path, warning = generate_npm_lockfile(repo, tmp_path / "out", sandbox=sandbox)
    assert path is None
    assert warning.startswith("npm lockfile generation failed (failed, exit 1)")
    assert "npm ERR! code E401" in warning
    assert "line 39" in warning
    assert "line 5\n" not in warning  # only the tail
    assert "ghp_" not in warning  # secrets redacted

    killed = FakeSandbox(results={"lockfile": StepResult(StepStatus.FAILED, 137)}, lockfile=None)
    _, warning = generate_npm_lockfile(repo, tmp_path / "out", sandbox=killed)
    assert "exit 137" in warning
    assert "killed" in warning


def test_scan_records_the_lockfile_failure_cause(tmp_path, monkeypatch):
    """A failed generation shows its cause in the npm-lockfile tool run and the hint."""
    from guardian.orchestration.pipeline import NPM_LOCKFILE

    monkeypatch.setenv("GUARDIAN_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("GUARDIAN_NPM_LOCKFILE_GENERATION", "true")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    repo = tmp_path / "shop"
    repo.mkdir()
    (repo / "package.json").write_text('{"name": "shop", "dependencies": {"ms": "2.1.3"}}')
    failing = FakeSandbox(
        results={"lockfile": StepResult(StepStatus.FAILED, 1, 1.0, "npm ERR! network ETIMEDOUT")},
        lockfile=None,
    )
    monkeypatch.setattr(scan_cli, "docker_sandbox", lambda s: failing)
    result = cli.invoke(app, ["scan", str(repo), "--json"])
    payload = json.loads(result.stdout)
    (run,) = [t for t in payload["scan"]["tool_runs"] if t["tool"] == NPM_LOCKFILE]
    assert run["status"] == "failed"
    assert "exit 1" in run["error"]
    assert "ETIMEDOUT" in run["error"]
    assert (
        failing.runs[0]["timeout"]
        == runtime.sandbox_config(GuardianSettings()).install_timeout_seconds
    )
    flat = " ".join(result.output.split())
    assert "generating one in the Docker sandbox failed" in flat


def test_scan_sandbox_uses_the_long_sandbox_timeout(settings):
    sandbox = runtime.docker_sandbox(settings)
    assert sandbox.config.install_timeout_seconds == settings.sandbox_timeout_seconds == 900
    assert sandbox.runner.policy.timeout_seconds == settings.sandbox_timeout_seconds
    assert settings.sandbox_timeout_seconds > settings.tool_timeout_seconds


def test_lockfile_hints_follow_the_generation_outcome(tmp_path):
    from juice_shop import profile

    from guardian.core.models import ToolRunSummary

    shop = profile(tmp_path)
    assert "Start Docker Desktop and rescan" in scan_cli.lockfile_hints(shop)[0]
    failed = [ToolRunSummary(tool="npm-lockfile", status="failed", error="x")]
    assert "sandbox failed" in scan_cli.lockfile_hints(shop, failed)[0]
    ok = [ToolRunSummary(tool="npm-lockfile", status="success")]
    assert scan_cli.lockfile_hints(shop, ok) == []

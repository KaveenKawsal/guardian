import httpx
import pytest
import typer
from jira_fake import (
    APPROVER_ID,
    BASE_URL,
    EMAIL,
    TOKEN,
    FakeJira,
    seed_case,
    seed_scan,
)
from remediation_fakes import stub_runtime
from typer.testing import CliRunner

from guardian.cli import decide as decide_module
from guardian.cli import jira as jira_module
from guardian.cli.decide import command_line, decide
from guardian.cli.jira import jira_app
from guardian.core.models import Priority
from guardian.core.remediation_models import CaseStatus, DeclineReason
from guardian.storage.database import Database

cli = CliRunner()
app = typer.Typer()
app.add_typer(jira_app)
app.command()(decide)


@pytest.fixture
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    data = tmp_path / "data"
    values = {
        "GUARDIAN_DATA_DIR": str(data),
        "JIRA_BASE_URL": BASE_URL,
        "JIRA_EMAIL": EMAIL,
        "JIRA_API_TOKEN": TOKEN,
        "JIRA_PROJECT_KEY": "SEC",
        "GUARDIAN_APPROVERS": APPROVER_ID,
        "GUARDIAN_CLI_APPROVERS": "alice",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    fake = FakeJira()
    monkeypatch.setattr(jira_module, "make_client", lambda settings: fake.client())
    monkeypatch.setattr(decide_module, "current_user", lambda: "alice")
    stub_runtime(monkeypatch)
    with Database(data / "guardian.db") as db:
        seed_scan(db)
    return fake, data / "guardian.db"


def _db(path):
    return Database(path)


def test_decide_accept_authorized(env):
    _, path = env
    with _db(path) as db:
        case = seed_case(db)[0]
    result = cli.invoke(app, ["decide", case.id, "accept"])
    assert result.exit_code == 0, result.output
    assert "now CLOSED" in result.output
    assert "Verdict: VERIFIED" in result.output
    with _db(path) as db:
        decision = db.remediation.decisions(case.id)[0]
        assert decision.channel == "cli"
        assert decision.actor_id == "alice"
        assert db.remediation.get(case.id).status is CaseStatus.CLOSED
        events = [e.event for e in db.audit.list(case.id)]
        assert "status:AWAITING_DECISION->APPROVED" in events
        assert "status:VALIDATING->VERIFIED" in events


def test_decide_decline_accepted_risk(env):
    _, path = env
    with _db(path) as db:
        case = seed_case(db)[0]
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
    with _db(path) as db:
        decision = db.remediation.decisions(case.id)[0]
        assert decision.decline_reason is DeclineReason.ACCEPTED_RISK
        assert decision.justification == "intentional training vuln"
        assert db.remediation.get(case.id).status is CaseStatus.CLOSED


def test_decide_unauthorized_user(env, monkeypatch):
    _, path = env
    monkeypatch.setattr(decide_module, "current_user", lambda: "mallory")
    with _db(path) as db:
        case = seed_case(db)[0]
    result = cli.invoke(app, ["decide", case.id, "accept"])
    assert result.exit_code == 3
    assert "not in GUARDIAN_CLI_APPROVERS" in result.output
    with _db(path) as db:
        assert not db.remediation.decisions(case.id)
        assert db.remediation.get(case.id).status is CaseStatus.AWAITING_DECISION
        assert "cli:unauthorized" in [e.event for e in db.audit.list(case.id)]


def test_decide_parse_error_and_wrong_state(env):
    _, path = env
    with _db(path) as db:
        case = seed_case(db)[0]
    result = cli.invoke(app, ["decide", case.id, "modify", "version=banana"])
    assert result.exit_code == 2
    assert "semantic version" in result.output
    result = cli.invoke(app, ["decide", case.id, "revalidate"])
    assert result.exit_code == 2
    assert "decision ignored" in result.output
    result = cli.invoke(app, ["decide", "rc_missing", "accept"])
    assert result.exit_code == 2
    with _db(path) as db:
        assert not db.remediation.decisions(case.id)


def test_command_line_reconstruction():
    assert command_line("accept", [], None) == "/guardian accept"
    assert command_line("modify", ["version=1.2.3"], None) == "/guardian modify version=1.2.3"
    assert command_line("decline", ["reason=wont_fix", "not", "used"], None) == (
        "/guardian decline reason=wont_fix -- not used"
    )
    assert command_line("decline", ["reason=wont_fix"], "why") == (
        "/guardian decline reason=wont_fix -- why"
    )
    assert command_line("decline", ["reason=duplicate", "--"], None) == (
        "/guardian decline reason=duplicate -- "
    )
    assert command_line("accept", ["--", "x=1"], None) == "/guardian accept -- x=1"


def test_jira_push_publishes_capped_cases(env):
    fake, path = env
    with _db(path) as db:
        high = seed_case(db, package="a", priority=Priority.P2, status=CaseStatus.PROPOSED)[0]
        low = seed_case(db, package="b", priority=Priority.P4)[0]
    result = cli.invoke(app, ["jira", "push", "latest"])
    assert result.exit_code == 0, result.output
    assert "1 published/updated, 1 skipped" in result.output
    assert len(fake.issues) == 1
    with _db(path) as db:
        assert db.remediation.get(high.id).jira_key == "SEC-1"
        assert db.remediation.get(high.id).status is CaseStatus.AWAITING_DECISION
        assert db.remediation.get(low.id).jira_key is None
    result = cli.invoke(app, ["jira", "push", "latest"])
    assert result.exit_code == 0
    assert len(fake.issues) == 1


def test_jira_push_without_cases_and_with_errors(env):
    fake, path = env
    result = cli.invoke(app, ["jira", "push"])
    assert result.exit_code == 0
    assert "No remediation cases" in result.output
    with _db(path) as db:
        seed_case(db)
    fake.queued = [httpx.Response(403, json={"errorMessages": ["nope"]})]
    result = cli.invoke(app, ["jira", "push"])
    assert result.exit_code == 1
    assert "HTTP 403" in result.output


def test_jira_sync_records_decision(env):
    fake, path = env
    with _db(path) as db:
        case = seed_case(db)[0]
        key = fake.add_issue(["guardian"])
        db.remediation.link_jira(case.id, key)
    fake.add_comment(key, APPROVER_ID, "/guardian accept")
    result = cli.invoke(app, ["jira", "sync"])
    assert result.exit_code == 0, result.output
    assert f"{case.id}: ACCEPT by Alice" in result.output
    assert "resuming the remediation graph" in result.output
    with _db(path) as db:
        assert db.remediation.get(case.id).status is CaseStatus.CLOSED
        assert len(db.remediation.decisions(case.id)) == 1  # the graph did not record it again


def test_jira_sync_watch_and_error(env, monkeypatch):
    fake, _ = env
    monkeypatch.setattr(
        jira_module.JiraSync, "watch", lambda self, on_report: on_report(self.sync_once())
    )
    result = cli.invoke(app, ["jira", "sync", "--watch"])
    assert result.exit_code == 0
    assert "Polling Jira every 30s" in result.output
    fake.queued = [httpx.Response(401)]
    result = cli.invoke(app, ["jira", "sync"])
    assert result.exit_code == 1
    assert "HTTP 401" in result.output


def test_jira_status(env):
    fake, _ = env
    result = cli.invoke(app, ["jira", "status"])
    assert result.exit_code == 0, result.output
    assert "Authenticated as Guardian Bot" in result.output
    assert TOKEN not in result.output
    assert "set (...6789)" in result.output
    fake.queued = [httpx.Response(401)]
    result = cli.invoke(app, ["jira", "status"])
    assert result.exit_code == 1
    assert "Authentication failed" in result.output
    assert TOKEN not in result.output


def test_jira_not_configured(env, monkeypatch):
    monkeypatch.setattr(jira_module, "make_client", jira_module.jira_client_from_settings)
    monkeypatch.setenv("JIRA_API_TOKEN", "")
    result = cli.invoke(app, ["jira", "sync"])
    assert result.exit_code == 2
    assert "JIRA_API_TOKEN" in result.output

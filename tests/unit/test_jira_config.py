import pytest
from pydantic import ValidationError

from guardian.core.config import GuardianSettings
from guardian.core.models import Priority
from guardian.execution.policies import ExecutionPolicy
from guardian.storage import database as database_module
from guardian.storage.database import SCHEMA_VERSION, Database

JIRA_ENV = (
    "JIRA_BASE_URL",
    "JIRA_EMAIL",
    "JIRA_API_TOKEN",
    "JIRA_PROJECT_KEY",
    "GUARDIAN_JIRA_BASE_URL",
    "GUARDIAN_JIRA_EMAIL",
    "GUARDIAN_JIRA_API_TOKEN",
    "GUARDIAN_JIRA_PROJECT_KEY",
    "GUARDIAN_JIRA_ISSUE_TYPE",
    "GUARDIAN_APPROVERS",
    "GUARDIAN_CLI_APPROVERS",
    "GUARDIAN_JIRA_MIN_PRIORITY",
    "GUARDIAN_JIRA_MAX_ISSUES",
    "GUARDIAN_JIRA_POLL_SECONDS",
    "GUARDIAN_JIRA_TRANSITIONS",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in JIRA_ENV:
        monkeypatch.delenv(name, raising=False)


def settings() -> GuardianSettings:
    return GuardianSettings(_env_file=None)


def test_defaults():
    s = settings()
    assert s.jira_base_url is None
    assert s.jira_api_token is None
    assert s.jira_issue_type == "Bug"
    assert s.approvers == []
    assert s.cli_approvers == []
    assert s.jira_min_priority is Priority.P2
    assert s.jira_max_issues == 5
    assert s.jira_poll_seconds == 30
    assert s.jira_transitions == {}
    assert not s.jira_configured


def test_env_aliases_and_parsing(monkeypatch):
    monkeypatch.setenv("JIRA_BASE_URL", "https://acme.atlassian.net/")
    monkeypatch.setenv("JIRA_EMAIL", " bot@acme.test ")
    monkeypatch.setenv("JIRA_API_TOKEN", "tok-1234567890abcdef")
    monkeypatch.setenv("JIRA_PROJECT_KEY", "SEC")
    monkeypatch.setenv("GUARDIAN_JIRA_ISSUE_TYPE", "Task")
    monkeypatch.setenv("GUARDIAN_APPROVERS", "acct-1, acct-2,,")
    monkeypatch.setenv("GUARDIAN_CLI_APPROVERS", "alice")
    monkeypatch.setenv("GUARDIAN_JIRA_MIN_PRIORITY", "critical")
    monkeypatch.setenv("GUARDIAN_JIRA_MAX_ISSUES", "3")
    monkeypatch.setenv("GUARDIAN_JIRA_POLL_SECONDS", "5")
    monkeypatch.setenv("GUARDIAN_JIRA_TRANSITIONS", '{"verified": "Done"}')
    s = settings()
    assert str(s.jira_base_url).startswith("https://acme.atlassian.net")
    assert s.jira_email == "bot@acme.test"
    assert s.jira_api_token is not None
    assert s.jira_api_token.get_secret_value() == "tok-1234567890abcdef"
    assert s.jira_project_key == "SEC"
    assert s.jira_issue_type == "Task"
    assert s.approvers == ["acct-1", "acct-2"]
    assert s.cli_approvers == ["alice"]
    assert s.jira_min_priority is Priority.P1
    assert s.jira_max_issues == 3
    assert s.jira_transitions == {"verified": "Done"}
    assert s.jira_configured
    assert "tok-1234567890abcdef" not in repr(s)


def test_blank_values_are_none(monkeypatch):
    for name in ("JIRA_BASE_URL", "JIRA_EMAIL", "JIRA_API_TOKEN", "JIRA_PROJECT_KEY"):
        monkeypatch.setenv(name, "  ")
    monkeypatch.setenv("GUARDIAN_APPROVERS", "")
    s = settings()
    assert (s.jira_base_url, s.jira_email, s.jira_api_token, s.jira_project_key) == (
        None,
        None,
        None,
        None,
    )
    assert s.approvers == []


def test_http_base_url_is_rejected(monkeypatch):
    monkeypatch.setenv("JIRA_BASE_URL", "http://acme.atlassian.net")
    with pytest.raises(ValidationError, match="https"):
        settings()


def test_bad_priority_and_transition_event(monkeypatch):
    monkeypatch.setenv("GUARDIAN_JIRA_MIN_PRIORITY", "urgent")
    with pytest.raises(ValidationError):
        settings()
    monkeypatch.delenv("GUARDIAN_JIRA_MIN_PRIORITY")
    monkeypatch.setenv("GUARDIAN_JIRA_TRANSITIONS", '{"merged": "Done"}')
    with pytest.raises(ValidationError):
        settings()


def test_subprocess_env_never_receives_jira_or_guardian_settings():
    """Regression: scanners and the sandbox must never see Jira credentials or settings."""
    source = {
        "PATH": "/usr/bin",
        "HOME": "/home/u",
        "JIRA_API_TOKEN": "secret",
        "JIRA_EMAIL": "a@b",
        "JIRA_BASE_URL": "https://x",
        "JIRA_PROJECT_KEY": "SEC",
        "GUARDIAN_JIRA_API_TOKEN": "secret",
        "GUARDIAN_APPROVERS": "acct",
        "GUARDIAN_CLI_APPROVERS": "alice",
        "guardian_jira_api_token": "secret",
        "GROQ_API_KEY": "secret",
    }
    env = ExecutionPolicy().build_env(source)
    assert env == {"PATH": "/usr/bin", "HOME": "/home/u"}
    leaked = [
        k for k in ExecutionPolicy().env_allowlist if k.upper().startswith(("JIRA", "GUARDIAN"))
    ]
    assert leaked == []


def test_migration_005_adds_kv_state(tmp_path, monkeypatch):
    path = tmp_path / "guardian.db"
    monkeypatch.setattr(
        database_module,
        "MIGRATIONS",
        {k: v for k, v in database_module.MIGRATIONS.items() if k <= 4},
    )
    with Database(path) as old:
        assert old.conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] == 4
    monkeypatch.undo()
    with Database(path) as db:
        version = db.conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
        assert version == SCHEMA_VERSION
        assert SCHEMA_VERSION >= 5
        assert db.kv.get("missing") is None
        db.kv.set("jira:last_sync_at", "a")
        db.kv.set("jira:last_sync_at", "b")
        assert db.kv.get("jira:last_sync_at") == "b"

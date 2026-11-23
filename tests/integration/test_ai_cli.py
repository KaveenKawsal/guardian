from pathlib import Path

import pytest
from langchain_core.language_models.fake_chat_models import FakeListChatModel
from typer.testing import CliRunner

from guardian.cli import ai as ai_cli
from guardian.cli.main import app
from guardian.llm import LLMProviderError
from guardian.llm import providers as providers_module

cli = CliRunner()
GROQ_KEY = "gsk_cli_test_key_0000wxyz"
GOOGLE_KEY = "AIza_cli_test_key_0000qrst"
ENV_VARS = (
    "GROQ_API_KEY",
    "GOOGLE_API_KEY",
    "GEMINI_API_KEY",
    "GUARDIAN_GROQ_API_KEY",
    "GUARDIAN_GOOGLE_API_KEY",
    "GUARDIAN_LLM_PROVIDER",
    "GUARDIAN_LLM_MODEL",
    "GUARDIAN_GROQ_MODEL",
    "GUARDIAN_GOOGLE_MODEL",
    "GUARDIAN_AI_ENABLED",
)


@pytest.fixture
def workspace(tmp_path, monkeypatch) -> tuple[Path, Path]:
    """Isolated home and working directory; returns (home env file, local env file)."""
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    home = tmp_path / "home"
    work = tmp_path / "work"
    home.mkdir()
    work.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda _: home))
    monkeypatch.chdir(work)
    return home / ".guardian" / ".env", work / ".env"


def write_home(home_env: Path, text: str) -> None:
    home_env.parent.mkdir(parents=True, exist_ok=True)
    home_env.write_text(text)


def test_status_masks_keys(workspace):
    home_env, _ = workspace
    write_home(home_env, f"GROQ_API_KEY={GROQ_KEY}\n")
    result = cli.invoke(app, ["ai", "status"])
    assert result.exit_code == 0, result.output
    assert GROQ_KEY not in result.output
    assert "...wxyz" in result.output
    assert "not set" in result.output
    assert "llama-3.3-70b-versatile" in result.output
    assert str(home_env) in "".join(result.output.split())


def test_status_without_provider_and_with_missing_key(workspace):
    result = cli.invoke(app, ["ai", "status"])
    assert result.exit_code == 0
    assert "No active provider" in result.output

    _, local_env = workspace
    local_env.write_text("GUARDIAN_LLM_PROVIDER=google\nGUARDIAN_LLM_MODEL=gemini-x\n")
    result = cli.invoke(app, ["ai", "status"])
    assert result.exit_code == 0
    assert "GOOGLE_API_KEY is not set" in result.output
    assert "gemini-x" in result.output


def test_status_ai_disabled(workspace, monkeypatch):
    monkeypatch.setenv("GUARDIAN_AI_ENABLED", "false")
    result = cli.invoke(app, ["ai", "status"])
    assert "AI is disabled" in result.output


def test_models_lists_and_marks_configured(workspace, monkeypatch):
    home_env, _ = workspace
    write_home(home_env, f"GOOGLE_API_KEY={GOOGLE_KEY}\nGUARDIAN_GOOGLE_MODEL=gemini-b\n")
    calls = []

    def fake_list(provider, api_key, **_):
        calls.append((provider, api_key.get_secret_value()))
        return ["gemini-a", "gemini-b"]

    monkeypatch.setattr(ai_cli, "list_models", fake_list)
    result = cli.invoke(app, ["ai", "models"])
    assert result.exit_code == 0, result.output
    assert calls == [("google", GOOGLE_KEY)]
    assert "gemini-a" in result.output
    assert "gemini-b" in result.output
    assert "not in the list" not in result.output


def test_models_warns_on_unknown_configured_model(workspace, monkeypatch):
    home_env, _ = workspace
    write_home(home_env, f"GROQ_API_KEY={GROQ_KEY}\n")
    monkeypatch.setattr(ai_cli, "list_models", lambda *_, **__: ["other"])
    result = cli.invoke(app, ["ai", "models", "--provider", "groq"])
    assert result.exit_code == 0
    assert "not in the list" in result.output


def test_models_errors(workspace, monkeypatch):
    result = cli.invoke(app, ["ai", "models"])
    assert result.exit_code == 2
    assert "No LLM provider" in result.output

    result = cli.invoke(app, ["ai", "models", "--provider", "groq"])
    assert result.exit_code == 2
    assert "console.groq.com/keys" in result.output

    home_env, _ = workspace
    write_home(home_env, f"GROQ_API_KEY={GROQ_KEY}\n")

    def rejected(*_, **__):
        msg = "Groq: API key rejected (HTTP 401)"
        raise LLMProviderError(msg)

    monkeypatch.setattr(ai_cli, "list_models", rejected)
    result = cli.invoke(app, ["ai", "models"])
    assert result.exit_code == 1
    assert "key rejected" in result.output
    assert GROQ_KEY not in result.output


def test_test_command_round_trip(workspace, monkeypatch):
    home_env, _ = workspace
    write_home(home_env, f"GROQ_API_KEY={GROQ_KEY}\n")
    seen = []

    def fake_build(config, settings):
        seen.append(config.model)
        return FakeListChatModel(responses=["OK"])

    monkeypatch.setattr(providers_module, "build_chat_model", fake_build)
    result = cli.invoke(app, ["ai", "test", "--model", "llama-x"])
    assert result.exit_code == 0, result.output
    assert "ok" in result.output
    assert "llama-x" in result.output
    assert seen == ["llama-x"]


def test_test_command_failures(workspace, monkeypatch):
    result = cli.invoke(app, ["ai", "test", "--provider", "google"])
    assert result.exit_code == 1
    assert "GOOGLE_API_KEY" in result.output

    home_env, _ = workspace
    write_home(home_env, f"GOOGLE_API_KEY={GOOGLE_KEY}\n")

    class Broken(FakeListChatModel):
        def _call(self, *args, **kwargs):
            msg = f"401 API key not valid: {GOOGLE_KEY}"
            raise RuntimeError(msg)

    monkeypatch.setattr(
        providers_module, "build_chat_model", lambda *_: Broken(responses=["unused"])
    )
    result = cli.invoke(app, ["ai", "test"])
    assert result.exit_code == 1
    assert "API key rejected" in result.output
    assert GOOGLE_KEY not in result.output


def test_use_writes_home_env_when_no_local_file(workspace):
    home_env, local_env = workspace
    result = cli.invoke(app, ["ai", "use", "google", "--model", "gemini-2.5-pro"])
    assert result.exit_code == 0, result.output
    assert not local_env.exists()
    assert home_env.read_text() == (
        "GUARDIAN_LLM_PROVIDER=google\nGUARDIAN_GOOGLE_MODEL=gemini-2.5-pro\n"
    )
    assert "GOOGLE_API_KEY is not set" in result.output

    status = cli.invoke(app, ["ai", "status"])
    assert "gemini-2.5-pro" in status.output


def test_use_updates_local_env_preserving_keys(workspace):
    _, local_env = workspace
    original = (
        f"# keys\nGROQ_API_KEY={GROQ_KEY}\nGUARDIAN_LLM_PROVIDER=google\nGUARDIAN_LLM_MODEL=x\n"
    )
    local_env.write_text(original)
    result = cli.invoke(app, ["ai", "use", "groq"])
    assert result.exit_code == 0, result.output
    assert local_env.read_text() == original.replace("PROVIDER=google", "PROVIDER=groq")
    assert "GUARDIAN_LLM_MODEL=x overrides" in result.output
    assert GROQ_KEY not in result.output


def test_use_reports_environment_override(workspace, monkeypatch):
    monkeypatch.setenv("GUARDIAN_LLM_PROVIDER", "google")
    result = cli.invoke(app, ["ai", "use", "groq"])
    assert result.exit_code == 0
    assert "overridden" in result.output


def test_use_rejects_unsafe_model(workspace):
    home_env, _ = workspace
    result = cli.invoke(app, ["ai", "use", "groq", "--model", "a b"])
    assert result.exit_code == 2
    assert not home_env.exists()


def test_tracebacks_hide_locals():
    assert app.pretty_exceptions_show_locals is False
    assert ai_cli.ai_app.pretty_exceptions_show_locals is False

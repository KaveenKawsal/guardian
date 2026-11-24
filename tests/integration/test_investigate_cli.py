"""``guardian investigate`` end to end over a stored scan (fake models, no network)."""

import pytest
import typer
from investigation import routes
from investigation_world import SCAN_ID, seed_ai_scan
from typer.testing import CliRunner

from guardian.cli import common
from guardian.cli import investigate as cli_module
from guardian.cli.investigate import investigate
from guardian.core.config import GuardianSettings
from guardian.storage.database import Database


@pytest.fixture(autouse=True)
def _no_real_providers(monkeypatch):
    """No test may reach Groq or Gemini, even when keys sit in .env or the environment."""
    for key in ("GROQ_API_KEY", "GOOGLE_API_KEY", "GUARDIAN_LLM_PROVIDER", "GUARDIAN_LLM_MODEL"):
        monkeypatch.delenv(key, raising=False)

    def refuse(*_args, **_kwargs):
        msg = "tests must use fake chat models"
        raise AssertionError(msg)

    monkeypatch.setattr("guardian.investigation.runner.build_chat_model", refuse)
    monkeypatch.setattr("guardian.llm.providers.build_chat_model", refuse)


def _app():
    app = typer.Typer()
    app.command()(investigate)
    app.command("noop")(lambda: None)  # keep subcommand dispatch
    return app


def _seed(tmp_path, monkeypatch):
    data = tmp_path / "data"
    monkeypatch.setenv("GUARDIAN_DATA_DIR", str(data))
    monkeypatch.setattr(cli_module, "env_files", lambda: ())
    # Other tests pin the shared console's width; never depend on what they left behind.
    monkeypatch.setattr(common.console, "width", 250)
    for key in ("GROQ_API_KEY", "GOOGLE_API_KEY", "GUARDIAN_LLM_PROVIDER"):
        monkeypatch.delenv(key, raising=False)
    settings = GuardianSettings(_env_file=None, data_dir=data)
    with Database(settings.database_path) as db:
        seed_ai_scan(db, tmp_path / "juice-shop")
    return settings


def test_investigate_no_ai(tmp_path, monkeypatch):
    settings = _seed(tmp_path, monkeypatch)
    result = CliRunner().invoke(
        _app(), ["investigate", "latest", "--no-ai", "--top", "2"], env={"COLUMNS": "200"}
    )
    assert result.exit_code == 0, result.output
    assert "AI off" in result.output
    assert "Code Investigator" in result.output
    assert "AI unavailable: AI disabled (--no-ai)" in result.output
    assert "0 LLM call(s)" in result.output
    with Database(settings.database_path) as db:
        run = db.investigations.latest_run(SCAN_ID)
        assert run is not None
        assert not run.ai_enabled


def test_investigate_with_fake_models(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch)
    real = cli_module.run_investigation

    def with_fakes(db, settings, scan_id, **kwargs):
        return real(db, settings, scan_id, routes=routes(), **kwargs)

    monkeypatch.setattr(cli_module, "run_investigation", with_fakes)
    result = CliRunner().invoke(
        _app(), ["investigate", SCAN_ID[:8], "--top", "1"], env={"COLUMNS": "220"}
    )
    assert result.exit_code == 0, result.output
    assert "Verdict (AI inference)" in result.output
    assert "exploitability: likely" in result.output
    assert "relevance: possible" in result.output
    assert "groq / fake-fast" in result.output
    assert "google / fake-deep" in result.output
    assert "Grounded claim." in result.output


def test_investigate_unknown_scan(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch)
    result = CliRunner().invoke(_app(), ["investigate", "nope", "--no-ai"])
    assert result.exit_code == 2
    assert "No scan matches" in result.output

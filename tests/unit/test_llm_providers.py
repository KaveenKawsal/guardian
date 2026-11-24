import json
import sys
from pathlib import Path

import httpx
import pytest
from langchain_core.language_models.fake_chat_models import FakeListChatModel
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_groq import ChatGroq
from pydantic import SecretStr

from guardian.core.config import GuardianSettings
from guardian.core.exceptions import ConfigurationError
from guardian.execution import runner as runner_module
from guardian.execution.policies import ExecutionPolicy
from guardian.execution.runner import ToolRunner
from guardian.llm import (
    LLMProviderError,
    active_provider,
    check_provider,
    get_chat_model,
    list_models,
    mask_secret,
    resolve_provider,
)
from guardian.llm.catalog import GOOGLE_MODELS_URL, GROQ_MODELS_URL
from guardian.llm.envfile import target_env_file, update_env_file
from guardian.llm.providers import safe_error_message

GROQ_KEY = "gsk_test_groq_key_000a1b2"
GOOGLE_KEY = "AIza_test_google_key_00c3d4"
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


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def settings(**values) -> GuardianSettings:
    return GuardianSettings(_env_file=None, **values)


# --- settings -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("env_name", "field"),
    [
        ("GROQ_API_KEY", "groq_api_key"),
        ("GUARDIAN_GROQ_API_KEY", "groq_api_key"),
        ("GOOGLE_API_KEY", "google_api_key"),
        ("GEMINI_API_KEY", "google_api_key"),
        ("GUARDIAN_GOOGLE_API_KEY", "google_api_key"),
    ],
)
def test_key_aliases_from_environment(monkeypatch, env_name, field):
    monkeypatch.setenv(env_name, "secret-value-1234")
    value = getattr(settings(), field)
    assert isinstance(value, SecretStr)
    assert value.get_secret_value() == "secret-value-1234"


def test_env_files_later_wins_and_aliases_work(tmp_path):
    home_env = tmp_path / "home.env"
    home_env.write_text(
        f"GROQ_API_KEY={GROQ_KEY}\nGUARDIAN_LLM_PROVIDER=google\nGUARDIAN_GROQ_MODEL=a\n"
    )
    local_env = tmp_path / "local.env"
    local_env.write_text(f"GEMINI_API_KEY={GOOGLE_KEY}\nGUARDIAN_LLM_PROVIDER=Groq\n")
    loaded = GuardianSettings(_env_file=(home_env, local_env))
    assert loaded.groq_api_key is not None
    assert loaded.groq_api_key.get_secret_value() == GROQ_KEY
    assert loaded.google_api_key is not None
    assert loaded.google_api_key.get_secret_value() == GOOGLE_KEY
    assert loaded.llm_provider == "groq"
    assert loaded.groq_model == "a"


def test_blank_values_are_unset(tmp_path):
    env = tmp_path / ".env"
    env.write_text("GROQ_API_KEY=\nGOOGLE_API_KEY=  \nGUARDIAN_LLM_PROVIDER=\n")
    loaded = GuardianSettings(_env_file=env)
    assert loaded.groq_api_key is None
    assert loaded.google_api_key is None
    assert loaded.llm_provider is None


def test_invalid_provider_rejected():
    with pytest.raises(ValueError, match="llm_provider"):
        settings(llm_provider="openai")


def test_keys_not_in_repr_or_dump():
    loaded = settings(groq_api_key=GROQ_KEY)
    assert GROQ_KEY not in repr(loaded)
    assert GROQ_KEY not in loaded.model_dump_json()


def test_mask_secret():
    assert mask_secret(None) == "not set"
    assert mask_secret(SecretStr("short")) == "set"
    assert mask_secret(SecretStr(GROQ_KEY)) == "set (...a1b2)"


# --- resolution ---------------------------------------------------------------------------


def test_no_keys_means_ai_off():
    assert resolve_provider(settings()) is None


def test_single_key_auto_selects_provider():
    config = resolve_provider(settings(google_api_key=GOOGLE_KEY))
    assert config is not None
    assert config.provider == "google"
    assert config.model == "gemini-3.5-flash"
    assert GOOGLE_KEY not in repr(config)


def test_two_keys_need_explicit_choice():
    both = settings(groq_api_key=GROQ_KEY, google_api_key=GOOGLE_KEY)
    assert active_provider(both) is None
    assert resolve_provider(both) is None
    chosen = settings(groq_api_key=GROQ_KEY, google_api_key=GOOGLE_KEY, llm_provider="google")
    config = resolve_provider(chosen)
    assert config is not None
    assert config.provider == "google"


def test_selected_provider_without_key_is_helpful():
    with pytest.raises(ConfigurationError, match=r"GROQ_API_KEY.*console\.groq\.com"):
        resolve_provider(settings(llm_provider="groq"))


def test_model_override_only_applies_to_active_provider():
    s = settings(
        groq_api_key=GROQ_KEY,
        google_api_key=GOOGLE_KEY,
        llm_provider="groq",
        llm_model="override",
        google_model="gemini-x",
    )
    groq = resolve_provider(s)
    assert groq is not None
    assert groq.model == "override"
    google = resolve_provider(s, provider="google")
    assert google is not None
    assert google.model == "gemini-x"
    explicit = resolve_provider(s, model="explicit")
    assert explicit is not None
    assert explicit.model == "explicit"


def test_ai_disabled():
    s = settings(groq_api_key=GROQ_KEY, ai_enabled=False)
    assert resolve_provider(s) is None
    assert resolve_provider(s, provider="groq") is not None
    with pytest.raises(ConfigurationError, match="disabled"):
        get_chat_model(s)


def test_get_chat_model_without_provider_raises():
    with pytest.raises(ConfigurationError, match="No LLM provider"):
        get_chat_model(settings())


def test_get_chat_model_groq():
    model = get_chat_model(
        settings(groq_api_key=GROQ_KEY, llm_temperature=0.2, llm_timeout_seconds=12)
    )
    assert isinstance(model, ChatGroq)
    assert model.model_name == "openai/gpt-oss-120b"
    assert model.groq_api_key is not None
    assert model.groq_api_key.get_secret_value() == GROQ_KEY
    assert model.temperature == 0.2
    assert model.request_timeout == 12
    assert model.max_retries == 2


def test_get_chat_model_google():
    model = get_chat_model(settings(google_api_key=GOOGLE_KEY), model="gemini-custom")
    assert isinstance(model, ChatGoogleGenerativeAI)
    assert model.model.removeprefix("models/") == "gemini-custom"
    assert model.google_api_key is not None
    assert model.google_api_key.get_secret_value() == GOOGLE_KEY
    assert model.temperature == 0
    assert model.timeout == 60
    assert model.max_retries == 2


# --- live model listing (mocked HTTP) -----------------------------------------------------


def mock_client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_list_groq_models():
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == GROQ_MODELS_URL
        assert request.headers["authorization"] == f"Bearer {GROQ_KEY}"
        return httpx.Response(
            200,
            json={
                "data": [
                    {"id": "llama-3.3-70b-versatile", "active": True},
                    {"id": "whisper-large-v3"},
                    {"id": "old-model", "active": False},
                    {"id": "b-model"},
                    {"no": "id"},
                ]
            },
        )

    names = list_models("groq", SecretStr(GROQ_KEY), client=mock_client(handler))
    assert names == ["b-model", "llama-3.3-70b-versatile"]


def test_list_google_models_paginates_and_filters():
    seen_tokens: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url).startswith(GOOGLE_MODELS_URL)
        assert request.headers["x-goog-api-key"] == GOOGLE_KEY
        assert GOOGLE_KEY not in str(request.url)
        token = request.url.params.get("pageToken")
        seen_tokens.append(token)
        if token is None:
            return httpx.Response(
                200,
                json={
                    "models": [
                        {
                            "name": "models/gemini-2.5-flash",
                            "supportedGenerationMethods": ["generateContent", "countTokens"],
                        },
                        {"name": "models/embedding-001", "supportedGenerationMethods": ["embed"]},
                    ],
                    "nextPageToken": "page2",
                },
            )
        return httpx.Response(
            200,
            json={
                "models": [
                    {
                        "name": "models/gemini-2.5-pro",
                        "supportedGenerationMethods": ["generateContent"],
                    }
                ]
            },
        )

    names = list_models("google", SecretStr(GOOGLE_KEY), client=mock_client(handler))
    assert names == ["gemini-2.5-flash", "gemini-2.5-pro"]
    assert seen_tokens == [None, "page2"]


@pytest.mark.parametrize("status", [401, 403])
def test_list_models_key_rejected(status):
    client = mock_client(lambda _: httpx.Response(status, json={"error": "bad key"}))
    with pytest.raises(LLMProviderError, match="key rejected") as info:
        list_models("groq", SecretStr(GROQ_KEY), client=client)
    assert GROQ_KEY not in str(info.value)


def test_list_models_server_error_and_bad_json():
    with pytest.raises(LLMProviderError, match="HTTP 500"):
        list_models(
            "google", SecretStr(GOOGLE_KEY), client=mock_client(lambda _: httpx.Response(500))
        )
    with pytest.raises(LLMProviderError, match="unexpected response"):
        list_models(
            "groq",
            SecretStr(GROQ_KEY),
            client=mock_client(lambda _: httpx.Response(200, content=b"not json")),
        )


def test_list_models_network_error_hides_key():
    def handler(request: httpx.Request) -> httpx.Response:
        msg = "connection refused"
        raise httpx.ConnectError(msg, request=request)

    with pytest.raises(LLMProviderError, match="could not list models") as info:
        list_models("groq", SecretStr(GROQ_KEY), client=mock_client(handler))
    assert GROQ_KEY not in str(info.value)
    assert info.value.__cause__ is None


def test_list_models_default_client(monkeypatch):
    created: list[httpx.Client] = []
    real_client = httpx.Client

    def factory(**kwargs):
        client = real_client(
            transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"data": []})),
            **kwargs,
        )
        created.append(client)
        return client

    monkeypatch.setattr(httpx, "Client", factory)
    assert list_models("groq", SecretStr(GROQ_KEY)) == []
    assert created[0].is_closed


# --- round-trip check ---------------------------------------------------------------------


def test_check_provider_success():
    result = check_provider(
        settings(groq_api_key=GROQ_KEY), chat_model=FakeListChatModel(responses=["OK"])
    )
    assert result.provider == "groq"
    assert result.model == "openai/gpt-oss-120b"
    assert result.reply == "OK"
    assert result.latency_seconds >= 0


class ExplodingChatModel(FakeListChatModel):
    status: int | None = None

    def _call(self, *args, **kwargs):
        error = RuntimeError(f"Error calling with key {GROQ_KEY}: model not found")
        error.status_code = self.status  # type: ignore[attr-defined]
        raise error


def test_check_provider_failure_redacts_key():
    with pytest.raises(LLMProviderError, match="model not found") as info:
        check_provider(
            settings(groq_api_key=GROQ_KEY),
            chat_model=ExplodingChatModel(responses=["unused"]),
        )
    assert GROQ_KEY not in str(info.value)
    assert info.value.__cause__ is None


def test_check_provider_auth_failure():
    with pytest.raises(LLMProviderError, match="API key rejected"):
        check_provider(
            settings(groq_api_key=GROQ_KEY),
            chat_model=ExplodingChatModel(responses=["unused"], status=401),
        )


def test_safe_error_message_truncates():
    message = safe_error_message(ValueError("x" * 1000))
    assert message.startswith("ValueError: ")
    assert len(message) < 400
    assert safe_error_message(ValueError()) == "ValueError"


# --- env file updates ---------------------------------------------------------------------


def test_update_env_file_preserves_other_lines(tmp_path):
    path = tmp_path / ".env"
    original = (
        "# my settings\r\n"
        f"GROQ_API_KEY={GROQ_KEY}\r\n"
        "# GUARDIAN_LLM_PROVIDER=google\r\n"
        "export guardian_llm_provider = google\r\n"
        "OTHER=1"
    )
    path.write_bytes(original.encode())
    update_env_file(path, {"GUARDIAN_LLM_PROVIDER": "groq", "GUARDIAN_GROQ_MODEL": "m-1"})
    assert path.read_bytes().decode() == (
        "# my settings\r\n"
        f"GROQ_API_KEY={GROQ_KEY}\r\n"
        "# GUARDIAN_LLM_PROVIDER=google\r\n"
        "GUARDIAN_LLM_PROVIDER=groq\r\n"
        "OTHER=1\r\n"
        "GUARDIAN_GROQ_MODEL=m-1\r\n"
    )


def test_update_env_file_creates_private_file(tmp_path):
    path = tmp_path / "home" / ".guardian" / ".env"
    update_env_file(path, {"GUARDIAN_LLM_PROVIDER": "google"})
    assert path.read_text() == "GUARDIAN_LLM_PROVIDER=google\n"
    if sys.platform != "win32":
        assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "updates",
    [
        {"GROQ_API_KEY": "x"},
        {"GUARDIAN_GROQ_MODEL": "bad\nGROQ_API_KEY=x"},
        {"GUARDIAN_GROQ_MODEL": ""},
    ],
)
def test_update_env_file_rejects_unsafe_updates(tmp_path, updates):
    path = tmp_path / ".env"
    with pytest.raises(ConfigurationError):
        update_env_file(path, updates)
    assert not path.exists()


def test_target_env_file(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda _: tmp_path / "home"))
    assert target_env_file(tmp_path) == tmp_path / "home" / ".guardian" / ".env"
    (tmp_path / ".env").write_text("")
    assert target_env_file(tmp_path) == tmp_path / ".env"


# --- keys never reach scanner subprocesses ------------------------------------------------


def test_api_keys_not_passed_to_tools(monkeypatch, tmp_path):
    monkeypatch.setattr(
        runner_module.shutil, "which", lambda tool: sys.executable if tool == "py" else None
    )
    for name in ("GROQ_API_KEY", "GOOGLE_API_KEY", "GEMINI_API_KEY", "GUARDIAN_GROQ_API_KEY"):
        monkeypatch.setenv(name, GROQ_KEY)
    runner = ToolRunner(ExecutionPolicy(allowed_tools=frozenset({"py"})))
    result = runner.run(
        "py",
        ["-c", "import json, os; print(json.dumps(dict(os.environ)))"],
        cwd=tmp_path,
    )
    child_env = {k.upper() for k in json.loads(result.stdout)}
    assert "GROQ_API_KEY" not in child_env
    assert "GOOGLE_API_KEY" not in child_env
    assert GROQ_KEY not in result.stdout

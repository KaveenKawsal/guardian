"""Provider resolution and the chat-model factory used by the AI investigation agents.

API keys stay inside :class:`pydantic.SecretStr` until the moment a client is built; nothing
here prints, logs or embeds them in exception messages.
"""

import time
from dataclasses import dataclass, field

from langchain_core.language_models import BaseChatModel
from pydantic import SecretStr

from guardian.core.config import LLM_PROVIDERS, GuardianSettings, LLMProvider
from guardian.core.exceptions import ConfigurationError, GuardianError

MAX_RETRIES = 2
MAX_ERROR_CHARS = 300
HTTP_UNAUTHORIZED = 401
HTTP_FORBIDDEN = 403

PROVIDER_LABELS: dict[LLMProvider, str] = {"groq": "Groq", "google": "Google AI (Gemini)"}
KEY_ENV_VARS: dict[LLMProvider, str] = {"groq": "GROQ_API_KEY", "google": "GOOGLE_API_KEY"}
KEY_URLS: dict[LLMProvider, str] = {
    "groq": "https://console.groq.com/keys",
    "google": "https://aistudio.google.com/apikey",
}
MODEL_ENV_VARS: dict[LLMProvider, str] = {
    "groq": "GUARDIAN_GROQ_MODEL",
    "google": "GUARDIAN_GOOGLE_MODEL",
}


class LLMProviderError(GuardianError):
    """A provider call failed (rejected key, network error, unknown model, ...)."""


@dataclass(frozen=True, slots=True)
class ProviderConfig:
    provider: LLMProvider
    model: str
    api_key: SecretStr = field(repr=False)

    @property
    def label(self) -> str:
        return PROVIDER_LABELS[self.provider]


@dataclass(frozen=True, slots=True)
class CheckResult:
    provider: LLMProvider
    model: str
    latency_seconds: float
    reply: str


def api_key_for(settings: GuardianSettings, provider: LLMProvider) -> SecretStr | None:
    return settings.groq_api_key if provider == "groq" else settings.google_api_key


def configured_model(settings: GuardianSettings, provider: LLMProvider) -> str:
    return settings.groq_model if provider == "groq" else settings.google_model


def mask_secret(secret: SecretStr | None) -> str:
    """Presence plus the last four characters (only for keys long enough to stay secret)."""
    if secret is None:
        return "not set"
    value = secret.get_secret_value()
    return f"set (...{value[-4:]})" if len(value) >= 12 else "set"  # noqa: PLR2004


def active_provider(settings: GuardianSettings) -> LLMProvider | None:
    """The selected provider, or the only provider with a key when none is selected."""
    if settings.llm_provider is not None:
        return settings.llm_provider
    with_keys = [p for p in LLM_PROVIDERS if api_key_for(settings, p) is not None]
    return with_keys[0] if len(with_keys) == 1 else None


def resolve_provider(
    settings: GuardianSettings,
    *,
    provider: LLMProvider | None = None,
    model: str | None = None,
) -> ProviderConfig | None:
    """Resolve provider, model and key; ``None`` when AI is off or no provider is chosen.

    An explicit ``provider`` is honoured even when ``ai_enabled`` is false (used by the CLI
    checks). Raises :class:`ConfigurationError` for a selected provider that has no key.
    """
    active = active_provider(settings)
    chosen = provider or (active if settings.ai_enabled else None)
    if chosen is None:
        return None
    key = api_key_for(settings, chosen)
    if key is None:
        msg = (
            f"{PROVIDER_LABELS[chosen]} is selected but no API key is configured. "
            f"Set {KEY_ENV_VARS[chosen]} in ./.env or ~/.guardian/.env "
            f"(get a key at {KEY_URLS[chosen]})."
        )
        raise ConfigurationError(msg)
    override = settings.llm_model if chosen == active else None
    return ProviderConfig(
        provider=chosen,
        model=model or override or configured_model(settings, chosen),
        api_key=key,
    )


def require_provider(
    settings: GuardianSettings,
    *,
    provider: LLMProvider | None = None,
    model: str | None = None,
) -> ProviderConfig:
    config = resolve_provider(settings, provider=provider, model=model)
    if config is None:
        if not settings.ai_enabled and provider is None:
            msg = "AI is disabled (GUARDIAN_AI_ENABLED=false)."
        else:
            msg = (
                "No LLM provider selected. Set GROQ_API_KEY or GOOGLE_API_KEY, then choose "
                "one with `guardian ai use groq|google` (or GUARDIAN_LLM_PROVIDER)."
            )
        raise ConfigurationError(msg)
    return config


def build_chat_model(config: ProviderConfig, settings: GuardianSettings) -> BaseChatModel:
    if config.provider == "groq":
        from langchain_groq import ChatGroq  # noqa: PLC0415 - heavy import, load on demand

        return ChatGroq(
            model=config.model,
            api_key=config.api_key,
            temperature=settings.llm_temperature,
            timeout=settings.llm_timeout_seconds,
            max_retries=MAX_RETRIES,
        )
    from langchain_google_genai import ChatGoogleGenerativeAI  # noqa: PLC0415

    return ChatGoogleGenerativeAI(
        model=config.model,
        api_key=config.api_key,
        temperature=settings.llm_temperature,
        timeout=settings.llm_timeout_seconds,
        max_retries=MAX_RETRIES,
    )


def get_chat_model(
    settings: GuardianSettings,
    *,
    provider: LLMProvider | None = None,
    model: str | None = None,
) -> BaseChatModel:
    """Chat model for the active (or given) provider; raises ``ConfigurationError`` if none."""
    return build_chat_model(require_provider(settings, provider=provider, model=model), settings)


def safe_error_message(exc: BaseException, secret: SecretStr | None = None) -> str:
    """Short, key-free description of a provider failure."""
    status = getattr(exc, "status_code", None) or getattr(exc, "code", None)
    text = str(exc)
    if secret is not None and (raw := secret.get_secret_value()):
        text = text.replace(raw, "***")
    lowered = text.lower()
    if status in {HTTP_UNAUTHORIZED, HTTP_FORBIDDEN} or any(
        marker in lowered
        for marker in ("invalid api key", "api key not valid", "api_key_invalid", "unauthorized")
    ):
        return "API key rejected by the provider (check that it is valid and not revoked)"
    text = " ".join(text.split())
    if len(text) > MAX_ERROR_CHARS:
        text = text[:MAX_ERROR_CHARS] + "..."
    return f"{type(exc).__name__}: {text}" if text else type(exc).__name__


def check_provider(
    settings: GuardianSettings,
    *,
    provider: LLMProvider | None = None,
    model: str | None = None,
    chat_model: BaseChatModel | None = None,
) -> CheckResult:
    """One tiny chat round-trip; raises :class:`LLMProviderError` on failure."""
    config = require_provider(settings, provider=provider, model=model)
    llm = chat_model or build_chat_model(config, settings)
    started = time.perf_counter()
    try:
        response = llm.invoke("Reply with OK")
    except Exception as exc:  # noqa: BLE001 - provider SDKs raise many unrelated types
        reason = safe_error_message(exc, config.api_key)
        msg = f"{config.label} model {config.model!r}: {reason}"
        # drop the chain: SDK exceptions can carry request details
        raise LLMProviderError(msg) from None
    latency = time.perf_counter() - started
    return CheckResult(
        provider=config.provider,
        model=config.model,
        latency_seconds=latency,
        reply=" ".join(response.text.split())[:80],
    )

"""Live model listing for each provider (plain HTTPS, keys sent only in headers)."""

from typing import Any

import httpx
from pydantic import SecretStr

from guardian.core.config import LLMProvider
from guardian.llm.providers import (
    HTTP_FORBIDDEN,
    HTTP_UNAUTHORIZED,
    PROVIDER_LABELS,
    LLMProviderError,
    safe_error_message,
)

GROQ_MODELS_URL = "https://api.groq.com/openai/v1/models"
GOOGLE_MODELS_URL = "https://generativelanguage.googleapis.com/v1beta/models"
LIST_TIMEOUT = httpx.Timeout(20.0, connect=10.0)
MAX_PAGES = 20
# Groq lists speech models alongside chat models; they cannot answer chat requests.
GROQ_NON_CHAT_MARKERS = ("whisper", "tts", "orpheus", "playai")


def list_models(
    provider: LLMProvider, api_key: SecretStr, *, client: httpx.Client | None = None
) -> list[str]:
    """Sorted chat-capable model ids; raises :class:`LLMProviderError` on any failure."""
    own_client = client is None
    http = client or httpx.Client(timeout=LIST_TIMEOUT, follow_redirects=False)
    try:
        if provider == "groq":
            return _groq_models(http, api_key)
        return _google_models(http, api_key)
    finally:
        if own_client:
            http.close()


def _get_json(
    http: httpx.Client,
    provider: LLMProvider,
    url: str,
    *,
    headers: dict[str, str],
    params: dict[str, str] | None = None,
) -> dict[str, Any]:
    label = PROVIDER_LABELS[provider]
    try:
        response = http.get(url, headers=headers, params=params, timeout=LIST_TIMEOUT)
    except httpx.HTTPError as exc:
        msg = f"{label}: could not list models ({safe_error_message(exc)})"
        raise LLMProviderError(msg) from None
    if response.status_code in {HTTP_UNAUTHORIZED, HTTP_FORBIDDEN}:
        msg = f"{label}: API key rejected (HTTP {response.status_code})"
        raise LLMProviderError(msg)
    if response.is_error:
        msg = f"{label}: could not list models (HTTP {response.status_code})"
        raise LLMProviderError(msg)
    try:
        data = response.json()
    except ValueError:
        data = None
    if not isinstance(data, dict):
        msg = f"{label}: unexpected response while listing models"
        raise LLMProviderError(msg)
    return data


def _groq_models(http: httpx.Client, api_key: SecretStr) -> list[str]:
    headers = {"Authorization": f"Bearer {api_key.get_secret_value()}"}
    data = _get_json(http, "groq", GROQ_MODELS_URL, headers=headers)
    models = {
        item["id"]
        for item in data.get("data") or []
        if isinstance(item, dict)
        and isinstance(item.get("id"), str)
        and item.get("active", True) is not False
        and not any(marker in item["id"].lower() for marker in GROQ_NON_CHAT_MARKERS)
    }
    return sorted(models)


def _google_models(http: httpx.Client, api_key: SecretStr) -> list[str]:
    headers = {"x-goog-api-key": api_key.get_secret_value()}
    models: set[str] = set()
    params = {"pageSize": "1000"}
    for _ in range(MAX_PAGES):
        data = _get_json(http, "google", GOOGLE_MODELS_URL, headers=headers, params=params)
        for item in data.get("models") or []:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                continue
            if "generateContent" in (item.get("supportedGenerationMethods") or []):
                models.add(item["name"].removeprefix("models/"))
        token = data.get("nextPageToken")
        if not isinstance(token, str) or not token:
            break
        params = {"pageSize": "1000", "pageToken": token}
    return sorted(models)

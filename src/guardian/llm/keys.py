"""Backup API keys and rate-limit pacing settings for the LLM providers.

Kept apart from :class:`~guardian.core.config.GuardianSettings` but read from the same env files
(``~/.guardian/.env`` then ``./.env``; real environment variables win). Keys stay inside
:class:`pydantic.SecretStr` and are excluded from ``repr``.

Backup keys only add capacity when they belong to a *different account*: Groq enforces its
tokens-per-minute limit per organization, so two keys of the same organization share one limit.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import (
    AliasChoices,
    Field,
    SecretStr,
    ValidationInfo,
    create_model,
    field_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

from guardian.core.config import GuardianSettings, LLMProvider, env_files
from guardian.llm.providers import KEY_ENV_VARS, api_key_for

MAX_BACKUP_KEYS = 9
MIN_MASKABLE_KEY_CHARS = 12


def backup_env_var(provider: LLMProvider, n: int) -> str:
    """``GROQ_API_KEY_BACKUP_<n>`` / ``GOOGLE_API_KEY_BACKUP_<n>``."""
    return f"{KEY_ENV_VARS[provider]}_BACKUP_{n}"


def _backup_field_name(provider: LLMProvider, n: int) -> str:
    return f"{provider}_api_key_backup_{n}"


class KeySettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="GUARDIAN_",
        env_file=(Path.home() / ".guardian" / ".env", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    groq_tokens_per_minute: int = Field(
        default=7000, gt=0, description="Pacing: Groq tokens per minute (free tier: 8000/org)"
    )
    groq_requests_per_minute: int = Field(default=25, gt=0)
    google_tokens_per_minute: int = Field(default=100_000, gt=0)
    google_requests_per_minute: int = Field(default=8, gt=0)
    llm_max_wait_seconds: float = Field(
        default=60.0, gt=0, description="Longest single wait for a cooling key before giving up"
    )

    @field_validator("*", mode="before")
    @classmethod
    def _blank_key_is_none(cls, value: object, info: ValidationInfo) -> object:
        if "_backup_" not in (info.field_name or ""):
            return value
        raw = value.get_secret_value() if isinstance(value, SecretStr) else value
        if isinstance(raw, str):
            raw = raw.strip()
            return raw or None
        return value


def _backup_fields() -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for provider in ("groq", "google"):
        for n in range(1, MAX_BACKUP_KEYS + 1):
            env = backup_env_var(provider, n)
            fields[_backup_field_name(provider, n)] = (
                SecretStr | None,
                Field(
                    default=None,
                    validation_alias=AliasChoices(f"GUARDIAN_{env}", env),
                    repr=False,
                ),
            )
    return fields


LLMKeySettings = create_model(
    "LLMKeySettings",
    __base__=KeySettings,
    __doc__="Backup keys (``<PROVIDER>_API_KEY_BACKUP_<n>``, n=1..9) and pacing settings.",
    **_backup_fields(),
)


def key_env_files() -> tuple[Path, ...]:
    """Same files and order as ``GuardianSettings`` (resolved at call time)."""
    return env_files()


def load_key_settings() -> KeySettings:
    return LLMKeySettings(_env_file=key_env_files())


@dataclass(frozen=True, slots=True)
class PoolKey:
    """One key of a provider's pool: its env var name and the secret."""

    index: int
    env_var: str
    secret: SecretStr = field(repr=False)

    @property
    def masked(self) -> str:
        value = self.secret.get_secret_value()
        return f"...{value[-4:]}" if len(value) >= MIN_MASKABLE_KEY_CHARS else "set"


def key_pool_entries(
    settings: GuardianSettings,
    provider: LLMProvider,
    backups: KeySettings | None = None,
) -> list[PoolKey]:
    """The primary key, then backups 1..9, de-duplicated by value (index = pool position)."""
    extra = backups if backups is not None else load_key_settings()
    candidates: list[tuple[str, SecretStr | None]] = [
        (KEY_ENV_VARS[provider], api_key_for(settings, provider))
    ]
    candidates.extend(
        (backup_env_var(provider, n), getattr(extra, _backup_field_name(provider, n), None))
        for n in range(1, MAX_BACKUP_KEYS + 1)
    )
    seen: set[str] = set()
    pool: list[PoolKey] = []
    for env_var, secret in candidates:
        if secret is None or secret.get_secret_value() in seen:
            continue
        seen.add(secret.get_secret_value())
        pool.append(PoolKey(len(pool), env_var, secret))
    return pool


def key_pool(
    settings: GuardianSettings,
    provider: LLMProvider,
    backups: KeySettings | None = None,
) -> list[SecretStr]:
    """Primary key then backups, de-duplicated."""
    return [k.secret for k in key_pool_entries(settings, provider, backups)]


def tokens_per_minute(keys: KeySettings, provider: LLMProvider) -> int:
    return keys.groq_tokens_per_minute if provider == "groq" else keys.google_tokens_per_minute


def requests_per_minute(keys: KeySettings, provider: LLMProvider) -> int:
    return keys.groq_requests_per_minute if provider == "groq" else keys.google_requests_per_minute

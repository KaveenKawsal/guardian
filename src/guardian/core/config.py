"""Runtime configuration, loaded from environment variables (``GUARDIAN_*``) and ``.env``."""

from pathlib import Path
from typing import Literal

from pydantic import AliasChoices, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

LLMProvider = Literal["groq", "google"]
LLM_PROVIDERS: tuple[LLMProvider, ...] = ("groq", "google")


def user_env_file() -> Path:
    """Per-user env file, so API keys work from any working directory."""
    return Path.home() / ".guardian" / ".env"


def env_files() -> tuple[Path, ...]:
    """Env files in load order: ``~/.guardian/.env`` then ``./.env`` (later wins)."""
    return (user_env_file(), Path(".env"))


DEFAULT_EXCLUDED_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        ".gradle",
        ".idea",
        ".vscode",
        "dist",
        "build",
        "target",
    }
)


class GuardianSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="GUARDIAN_",
        env_file=(Path.home() / ".guardian" / ".env", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    data_dir: Path = Field(default_factory=lambda: Path.home() / ".guardian")

    ai_enabled: bool = True
    llm_provider: LLMProvider | None = Field(
        default=None,
        description="Active LLM provider; unset picks the only provider with a key",
    )
    llm_model: str | None = Field(
        default=None, description="Model override for the active provider"
    )
    llm_temperature: float = Field(default=0.0, ge=0, le=2)
    llm_timeout_seconds: float = Field(default=60.0, gt=0)
    groq_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("GUARDIAN_GROQ_API_KEY", "GROQ_API_KEY"),
        repr=False,
    )
    google_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "GUARDIAN_GOOGLE_API_KEY", "GOOGLE_API_KEY", "GEMINI_API_KEY"
        ),
        repr=False,
    )
    groq_model: str = "llama-3.3-70b-versatile"
    google_model: str = "gemini-2.5-flash"

    tool_timeout_seconds: float = Field(default=300.0, gt=0)
    max_tool_output_bytes: int = Field(default=20 * 1024 * 1024, gt=0)

    max_sbom_bytes: int = Field(default=200 * 1024 * 1024, gt=0)

    semgrep_configs: list[str] | None = Field(
        default=None,
        description="Semgrep --config values; default selects registry packs per language",
    )
    semgrep_rule_timeout_seconds: float = Field(default=30.0, gt=0)
    change_history_commits: int = Field(default=50, ge=0)
    max_blamed_findings: int = Field(default=200, ge=0)

    index_source: bool = True
    max_source_bytes: int = Field(default=1024 * 1024, gt=0, description="Skip larger files")
    max_indexed_files: int = Field(default=20_000, gt=0)

    max_files: int = Field(default=200_000, gt=0)
    max_manifest_bytes: int = Field(default=5 * 1024 * 1024, gt=0)
    excluded_dirs: frozenset[str] = DEFAULT_EXCLUDED_DIRS

    @field_validator("llm_provider", "llm_model", mode="before")
    @classmethod
    def _blank_is_none(cls, value: object) -> object:
        if isinstance(value, str):
            value = value.strip()
            return value.lower() if value and value.lower() in LLM_PROVIDERS else value or None
        return value

    @field_validator("groq_api_key", "google_api_key", mode="before")
    @classmethod
    def _blank_key_is_none(cls, value: object) -> object:
        raw = value.get_secret_value() if isinstance(value, SecretStr) else value
        if isinstance(raw, str):
            raw = raw.strip()
            return SecretStr(raw) if raw else None
        return value

    @property
    def database_path(self) -> Path:
        return self.data_dir / "guardian.db"

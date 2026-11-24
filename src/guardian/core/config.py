"""Runtime configuration, loaded from environment variables (``GUARDIAN_*``) and ``.env``."""

import re
from pathlib import Path
from typing import Annotated, Literal

from pydantic import AliasChoices, Field, HttpUrl, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from guardian.core.models import Priority

LLMProvider = Literal["groq", "google"]
LLM_PROVIDERS: tuple[LLMProvider, ...] = ("groq", "google")

_REMOTE_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")

JiraTransitionEvent = Literal["approved", "declined", "verified", "validation_failed"]
"""Case events that can move the Jira issue through its workflow (optional)."""


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
    groq_model: str = "openai/gpt-oss-120b"
    google_model: str = "gemini-3.5-flash"

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

    # --- Jira human-in-the-loop (Milestone 4) -------------------------------------------
    jira_base_url: HttpUrl | None = Field(
        default=None,
        validation_alias=AliasChoices("GUARDIAN_JIRA_BASE_URL", "JIRA_BASE_URL", "jira_base_url"),
        description="Jira Cloud site, e.g. https://example.atlassian.net (https only)",
    )
    jira_email: str | None = Field(
        default=None,
        validation_alias=AliasChoices("GUARDIAN_JIRA_EMAIL", "JIRA_EMAIL", "jira_email"),
    )
    jira_api_token: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "GUARDIAN_JIRA_API_TOKEN", "JIRA_API_TOKEN", "jira_api_token"
        ),
        repr=False,
    )
    jira_project_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "GUARDIAN_JIRA_PROJECT_KEY", "JIRA_PROJECT_KEY", "jira_project_key"
        ),
    )
    jira_issue_type: str = "Bug"
    approvers: Annotated[list[str], NoDecode] = Field(
        default_factory=list,
        description="Jira accountIds allowed to decide (GUARDIAN_APPROVERS, comma-separated)",
    )
    cli_approvers: Annotated[list[str], NoDecode] = Field(
        default_factory=list,
        description="Local OS usernames allowed to run `guardian decide` (comma-separated)",
    )
    jira_min_priority: Priority = Priority.P2
    jira_max_issues: int = Field(default=5, ge=0)
    jira_poll_seconds: float = Field(default=30.0, gt=0)
    jira_transitions: dict[JiraTransitionEvent, str] = Field(
        default_factory=dict,
        description='Optional workflow transitions, e.g. {"verified": "Done"} (JSON)',
    )

    # --- Remediation sandbox (Milestone 5) -----------------------------------------------
    sandbox_cpus: str = Field(default="2", description="docker run --cpus")
    sandbox_memory: str = Field(default="4g", description="docker run --memory")
    sandbox_timeout_seconds: float = Field(
        default=900.0, gt=0, description="Wall-clock limit per sandbox step (install/build/test)"
    )
    max_parallel_fixes: int = Field(
        default=2,
        ge=1,
        le=8,
        description="Fixes built, tested and rescanned at the same time (each in its own "
        "sandbox); further accepted fixes wait for a free slot",
    )
    npm_lockfile_generation: bool = Field(
        default=True,
        description="Generate a missing package-lock.json in the Docker sandbox before scanning",
    )
    unsafe_host_validation: bool = Field(
        default=False,
        description="UNSAFE: build and test on the host when Docker is unavailable",
    )

    # --- Pull requests (optional, off by default) ------------------------------------------
    pr_enabled: bool = Field(
        default=False,
        description="Push guardian/fix-* and open a GitHub pull request after a VERIFIED fix",
    )
    pr_draft: bool = Field(default=True, description="Open pull requests as drafts")
    pr_remote: str = Field(
        default="origin",
        description="Git remote of the scanned repository that names the GitHub repository",
    )
    pr_base: str | None = Field(
        default=None, description="Base branch; unset uses the repository's default branch"
    )
    github_token: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "GUARDIAN_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "github_token"
        ),
        repr=False,
        description="Token with contents:write and pull_requests:write on the repository",
    )

    @field_validator("llm_provider", "llm_model", mode="before")
    @classmethod
    def _blank_is_none(cls, value: object) -> object:
        if isinstance(value, str):
            value = value.strip()
            return value.lower() if value and value.lower() in LLM_PROVIDERS else value or None
        return value

    @field_validator(
        "groq_api_key", "google_api_key", "jira_api_token", "github_token", mode="before"
    )
    @classmethod
    def _blank_key_is_none(cls, value: object) -> object:
        raw = value.get_secret_value() if isinstance(value, SecretStr) else value
        if isinstance(raw, str):
            raw = raw.strip()
            return SecretStr(raw) if raw else None
        return value

    @field_validator("jira_base_url", mode="before")
    @classmethod
    def _https_jira_url(cls, value: object) -> object:
        if isinstance(value, str):
            value = value.strip().rstrip("/")
            if not value:
                return None
            if not value.lower().startswith("https://"):
                msg = "JIRA_BASE_URL must use https://"
                raise ValueError(msg)
        return value

    @field_validator("jira_email", "jira_project_key", "pr_base", mode="before")
    @classmethod
    def _blank_text_is_none(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip() or None
        return value

    @field_validator("pr_remote", mode="after")
    @classmethod
    def _safe_remote_name(cls, value: str) -> str:
        value = value.strip()
        if not _REMOTE_NAME_RE.fullmatch(value):
            msg = "GUARDIAN_PR_REMOTE must be a plain git remote name (letters, digits, ._-)"
            raise ValueError(msg)
        return value

    @field_validator("approvers", "cli_approvers", mode="before")
    @classmethod
    def _comma_separated(cls, value: object) -> object:
        if value is None:
            return []
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return value

    @field_validator("jira_min_priority", mode="before")
    @classmethod
    def _parse_priority(cls, value: object) -> object:
        if isinstance(value, str):
            return Priority.parse(value)
        return value

    @property
    def jira_configured(self) -> bool:
        return None not in (
            self.jira_base_url,
            self.jira_email,
            self.jira_api_token,
            self.jira_project_key,
        )

    @property
    def database_path(self) -> Path:
        return self.data_dir / "guardian.db"

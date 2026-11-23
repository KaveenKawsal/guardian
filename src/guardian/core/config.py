"""Runtime configuration, loaded from environment variables (``GUARDIAN_*``) and ``.env``."""

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

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
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    data_dir: Path = Field(default_factory=lambda: Path.home() / ".guardian")

    ai_enabled: bool = True
    llm_provider: str | None = None
    llm_model: str | None = None

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

    @property
    def database_path(self) -> Path:
        return self.data_dir / "guardian.db"

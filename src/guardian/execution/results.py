"""Normalized result of running an external tool."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class ToolStatus(StrEnum):
    SUCCESS = "success"
    FAILED = "failed"
    """The tool ran and exited non-zero. Some scanners use this to signal findings."""
    TIMEOUT = "timeout"
    NOT_FOUND = "not_found"
    ERROR = "error"
    """The process could not be started."""
    SKIPPED = "skipped"
    """Guardian decided not to run the tool (nothing to analyse, or disabled)."""


class ToolResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    tool: str
    args: list[str]
    status: ToolStatus
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.0
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.status is ToolStatus.SUCCESS

    @property
    def ran(self) -> bool:
        """True if the process started and exited on its own, regardless of exit code."""
        return self.status in {ToolStatus.SUCCESS, ToolStatus.FAILED}

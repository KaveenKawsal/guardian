"""Shared types for deterministic analyzers."""

import hashlib
from collections.abc import Collection
from dataclasses import dataclass, field

from guardian.core.models import ChangeRecord, Finding, ToolRunSummary
from guardian.execution.results import ToolResult, ToolStatus


@dataclass
class AnalysisResult:
    tool_run: ToolRunSummary
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    changes: list[ChangeRecord] = field(default_factory=list)


def decode_tool_output(data: str | bytes) -> str:
    """Decode scanner output that should be UTF-8 but may not be.

    On Windows, Python-based tools (Semgrep) can write files in the ANSI code page. Invalid
    bytes are replaced rather than failing the whole analysis.
    """
    if isinstance(data, str):
        return data
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace")


def stable_id(*parts: str | None) -> str:
    """Deterministic identifier so the same issue keeps its id across scans."""
    digest = hashlib.sha256("\x1f".join(p or "" for p in parts).encode("utf-8"))
    return digest.hexdigest()[:16]


def summarize(
    result: ToolResult, ok_exit_codes: Collection[int] = (0,), error: str | None = None
) -> ToolRunSummary:
    """Summarize a tool run. Exit codes in ``ok_exit_codes`` count as success.

    Scanners commonly exit non-zero to signal "findings present" (osv-scanner exits 1), which
    is not a failure.
    """
    status = result.status
    if result.ran and result.exit_code in ok_exit_codes:
        status = ToolStatus.SUCCESS
    elif result.status is ToolStatus.SUCCESS:
        status = ToolStatus.FAILED  # exit 0 but caller-detected problem (e.g. bad output)

    if error is None and status is not ToolStatus.SUCCESS:
        error = result.error
        if error is None:
            lines = [line for line in result.stderr.strip().splitlines() if line.strip()]
            error = lines[-1][:500] if lines else f"exited with code {result.exit_code}"
    return ToolRunSummary(
        tool=result.tool,
        status=status.value,
        exit_code=result.exit_code,
        duration_seconds=round(result.duration_seconds, 3),
        error=error,
    )


def skipped(tool: str, reason: str) -> AnalysisResult:
    return AnalysisResult(
        tool_run=ToolRunSummary(tool=tool, status=ToolStatus.SKIPPED.value, error=reason)
    )

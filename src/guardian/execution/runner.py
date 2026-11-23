"""Safe execution of external security tools."""

import shutil
import subprocess
import time
from collections.abc import Mapping, Sequence
from pathlib import Path

from guardian.core.exceptions import ToolNotAllowedError, UnsafeArgumentError
from guardian.execution.policies import GIT_HARDENING_ARGS, GIT_HARDENING_ENV, ExecutionPolicy
from guardian.execution.results import ToolResult, ToolStatus

# On Windows, .bat/.cmd files are run through cmd.exe, which re-parses arguments and makes
# these characters capable of command injection even without shell=True.
_CMD_METACHARACTERS = frozenset('&|<>^%!"\r\n')
_BATCH_SUFFIXES = frozenset({".bat", ".cmd"})


class ToolRunner:
    def __init__(self, policy: ExecutionPolicy | None = None) -> None:
        self.policy = policy or ExecutionPolicy()

    def resolve(self, tool: str) -> str | None:
        """Absolute path of an allowed tool, or ``None`` if it is not installed."""
        self._check_allowed(tool)
        return shutil.which(tool)

    def is_available(self, tool: str) -> bool:
        return self.resolve(tool) is not None

    def run(
        self,
        tool: str,
        args: Sequence[str],
        *,
        cwd: Path,
        timeout_seconds: float | None = None,
        env: Mapping[str, str] | None = None,
    ) -> ToolResult:
        """Run ``tool`` with ``args``. Never raises for tool failures; inspect ``status``.

        ``env`` adds tool-specific variables on top of the scrubbed policy environment.

        Raises ``ToolNotAllowedError`` / ``UnsafeArgumentError`` for programming errors.
        """
        args = list(args)
        executable = self.resolve(tool)
        if executable is None:
            return ToolResult(
                tool=tool,
                args=args,
                status=ToolStatus.NOT_FOUND,
                error=f"{tool!r} was not found on PATH",
            )
        if Path(executable).suffix.lower() in _BATCH_SUFFIXES:
            _reject_cmd_metacharacters(tool, args)

        child_env = self.policy.build_env()
        child_env.update(env or {})
        # Every tool may run git inside the scanned repository, so all of them get the git
        # hardening; it is applied last so callers cannot weaken it.
        child_env.update(GIT_HARDENING_ENV)
        argv = [executable]
        if tool == "git":
            argv += GIT_HARDENING_ARGS
        argv += args

        timeout = timeout_seconds or self.policy.timeout_seconds
        started = time.monotonic()
        try:
            completed = subprocess.run(
                argv,
                cwd=cwd,
                env=child_env,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            stdout, out_cut = self._decode(exc.stdout)
            stderr, err_cut = self._decode(exc.stderr)
            return ToolResult(
                tool=tool,
                args=args,
                status=ToolStatus.TIMEOUT,
                stdout=stdout,
                stderr=stderr,
                stdout_truncated=out_cut,
                stderr_truncated=err_cut,
                duration_seconds=time.monotonic() - started,
                error=f"{tool} timed out after {timeout:g}s",
            )
        except OSError as exc:
            return ToolResult(
                tool=tool,
                args=args,
                status=ToolStatus.ERROR,
                duration_seconds=time.monotonic() - started,
                error=f"Failed to start {tool}: {exc}",
            )

        stdout, out_cut = self._decode(completed.stdout)
        stderr, err_cut = self._decode(completed.stderr)
        return ToolResult(
            tool=tool,
            args=args,
            status=ToolStatus.SUCCESS if completed.returncode == 0 else ToolStatus.FAILED,
            exit_code=completed.returncode,
            stdout=stdout,
            stderr=stderr,
            stdout_truncated=out_cut,
            stderr_truncated=err_cut,
            duration_seconds=time.monotonic() - started,
        )

    def _check_allowed(self, tool: str) -> None:
        if tool not in self.policy.allowed_tools:
            msg = f"Tool {tool!r} is not permitted by the execution policy"
            raise ToolNotAllowedError(msg)

    def _decode(self, data: bytes | str | None) -> tuple[str, bool]:
        if data is None:
            return "", False
        raw = data.encode() if isinstance(data, str) else data
        limit = self.policy.max_output_bytes
        truncated = len(raw) > limit
        return raw[:limit].decode("utf-8", errors="replace"), truncated


def _reject_cmd_metacharacters(tool: str, args: Sequence[str]) -> None:
    for arg in args:
        if bad := _CMD_METACHARACTERS.intersection(arg):
            msg = (
                f"Refusing to pass argument {arg!r} to batch wrapper for {tool!r}: "
                f"contains {''.join(sorted(bad))!r}"
            )
            raise UnsafeArgumentError(msg)

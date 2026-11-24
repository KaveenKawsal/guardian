"""npm lockfile generation inside the sandbox.

Juice Shop ships no lockfile (``.npmrc`` sets ``package-lock=false``), and cdxgen/OSV need one to
see the resolved tree. Guardian generates it with

    npm install --package-lock-only --package-lock=true --ignore-scripts --no-audit --no-fund

in the sandbox (network on, install scripts off) on a disposable copy that contains only
``package.json`` (and an existing ``package-lock.json``, if any, so pins are kept). The
repository's ``.npmrc`` is deliberately *not* copied: it is repository-controlled and could
redirect the registry. The resulting ``package-lock.json`` is copied OUT to ``out_dir`` (a scan
workspace); nothing is ever written into the user's repository.
"""

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from guardian.core.remediation_models import StepStatus
from guardian.indexing.code_retriever import redact_secrets
from guardian.remediation.sandbox import (
    NPM,
    Sandbox,
    StepResult,
    container_name,
    make_work_dir,
    random_suffix,
    read_regular_file,
)

NPM_LOCKFILE_COMMAND: tuple[str, ...] = (
    NPM,
    "install",
    "--package-lock-only",
    "--package-lock=true",
    "--ignore-scripts",
    "--no-audit",
    "--no-fund",
)
LOCKFILE_NAME = "package-lock.json"


@dataclass(frozen=True)
class LockfileOutcome:
    path: Path | None
    warning: str | None
    step: StepResult


FAILURE_TAIL_LINES = 20
FAILURE_TAIL_CHARS = 2_000


def failure_warning(step: StepResult) -> str:
    """One warning naming the status, exit code, detail and the last lines of output (secrets
    redacted), so a failed generation says why instead of a bare "failed"."""
    exit_code = "no exit code" if step.exit_code is None else f"exit {step.exit_code}"
    head = f"npm lockfile generation failed ({step.status.value}, {exit_code})"
    if step.detail:
        head += f": {step.detail}"
    clean, _ = redact_secrets(step.output or "")
    lines = [line for line in clean.splitlines() if line.strip()]
    tail = "\n".join(lines[-FAILURE_TAIL_LINES:])[-FAILURE_TAIL_CHARS:]
    if not tail and step.exit_code is not None and step.exit_code >= 128:  # noqa: PLR2004
        tail = "the container was killed (signal or out of memory)"
    return f"{head}\n{tail}" if tail else head


def generate_npm_lockfile_step(
    repo_or_worktree: Path, out_dir: Path, sandbox: Sandbox, *, name: str | None = None
) -> LockfileOutcome:
    """Generate ``out_dir/package-lock.json`` for ``repo_or_worktree/package.json``."""
    config = sandbox.config
    ok, reason = sandbox.available()
    if not ok:
        warning = f"npm lockfile generation skipped: sandbox unavailable: {reason}"
        return LockfileOutcome(None, warning, StepResult(StepStatus.SKIPPED, detail=warning))

    package_json = read_regular_file(repo_or_worktree / "package.json", config.max_manifest_bytes)
    if package_json is None:
        warning = "npm lockfile generation skipped: no readable package.json"
        return LockfileOutcome(None, warning, StepResult(StepStatus.SKIPPED, detail=warning))
    try:
        json.loads(package_json)
    except (ValueError, UnicodeDecodeError):
        warning = "npm lockfile generation skipped: package.json is not valid JSON"
        return LockfileOutcome(None, warning, StepResult(StepStatus.FAILED, detail=warning))

    work = make_work_dir(config, "guardian-lock-")
    try:
        ctx = work / "ctx"
        ctx.mkdir()
        ctx.chmod(0o777)  # disposable, inside a 0700 temp dir; uid 1000 writes
        (ctx / "package.json").write_bytes(package_json)
        existing = read_regular_file(repo_or_worktree / LOCKFILE_NAME, config.max_lockfile_bytes)
        if existing is not None:
            (ctx / LOCKFILE_NAME).write_bytes(existing)
            (ctx / LOCKFILE_NAME).chmod(0o666)
        step = sandbox.run(
            config.base_image,
            ctx,
            NPM_LOCKFILE_COMMAND,
            network=config.install_network,
            timeout=config.install_timeout_seconds,
            name=name or container_name("lockfile", random_suffix()),
        )
        if step.status is not StepStatus.PASSED:
            return LockfileOutcome(None, failure_warning(step), step)
        produced = read_regular_file(ctx / LOCKFILE_NAME, config.max_lockfile_bytes)
        if produced is None:
            warning = "npm lockfile generation produced no usable package-lock.json"
            return LockfileOutcome(None, warning, step)
        out_dir.mkdir(parents=True, exist_ok=True)
        target = out_dir / LOCKFILE_NAME
        target.write_bytes(produced)
        return LockfileOutcome(target, None, step)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def generate_npm_lockfile(
    repo_or_worktree: Path, out_dir: Path, sandbox: Sandbox
) -> tuple[Path | None, str | None]:
    """Returns ``(lockfile path in out_dir, None)`` or ``(None, warning)``.

    Matches ``orchestration.pipeline.LockfileGenerator`` once ``sandbox`` is bound, e.g.
    ``functools.partial(generate_npm_lockfile, sandbox=DockerSandbox())``.
    """
    outcome = generate_npm_lockfile_step(repo_or_worktree, out_dir, sandbox)
    return outcome.path, outcome.warning

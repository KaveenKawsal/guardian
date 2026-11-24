"""Sandboxed validation of an applied fix: install, build, test (rule 9).

Phase 1 (network on, install scripts off):
    ``install`` = regenerate ``package-lock.json`` for the post-fix ``package.json``
    (``npm install --package-lock-only --package-lock=true --ignore-scripts``), then build or
    reuse the ``guardian-deps:<hash>`` image (``npm ci --ignore-scripts``).
Phase 2 (``--network none``, in that image, on a disposable copy of the worktree):
    ``build`` and ``test`` per ``node_script_plan``.

Which npm scripts run is an explicit table, not a guess: a Juice Shop-like project (it defines
``build:server``/``test:server``) runs exactly those two; a generic npm project runs
``npm test`` only when a real ``test`` script exists. ``NEVER_RUN_SCRIPTS`` (``postinstall``,
``test:frontend``, ``test:api`` ...) are never invoked.

Without a sandbox nothing runs: every step is skipped with ``sandbox unavailable: <reason>`` and
the run's sandbox is ``none`` (verification then yields UNVERIFIED). ``unsafe_host=True`` runs
the same steps on the host instead, with a loud warning; such a run is recorded as
``host-unsafe`` and can never be VERIFIED.

Logs go to ``<guardian_home>/logs/<case_id>/<run>/<step>.log``, secrets redacted, size-capped.
"""

import json
import shutil
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from guardian.core.remediation_models import (
    RemediationCase,
    StepStatus,
    ValidationRun,
    ValidationStep,
)
from guardian.indexing.code_retriever import redact_secrets
from guardian.remediation.apply import AppliedChange
from guardian.remediation.lockfile import LOCKFILE_NAME, generate_npm_lockfile_step
from guardian.remediation.sandbox import (
    NPM,
    HostSandbox,
    Sandbox,
    SandboxConfig,
    StepResult,
    container_name,
    copy_tree,
    make_work_dir,
    random_suffix,
    read_regular_file,
)
from guardian.remediation.testparse import (
    KNOWN_CONFLICT_DETAIL,
    TestSummary,
    is_known_conflict,
    parse_node_test_output,
)
from guardian.storage.database import Database
from guardian.storage.remediation import SYSTEM_ACTOR

StepName = Literal["install", "build", "test"]
STEP_NAMES: tuple[StepName, ...] = ("install", "build", "test")

NEVER_RUN_SCRIPTS: frozenset[str] = frozenset(
    {
        "preinstall",
        "install",
        "postinstall",
        "prepare",
        "prepublish",
        "prepublishOnly",
        "test:frontend",
        "test:api",
    }
)
NPM_DEFAULT_TEST = 'echo "Error: no test specified" && exit 1'


@dataclass(frozen=True)
class NodeScriptProfile:
    name: str
    markers: frozenset[str]
    """The profile applies when package.json defines any of these scripts."""
    build_script: str | None
    test_script: str | None


NODE_SCRIPT_PROFILES: tuple[NodeScriptProfile, ...] = (
    # OWASP Juice Shop: `build:server` = tsc, `test:server` = node --test via tsx. Its
    # `postinstall` builds the Angular frontend and `test:frontend`/`test:api` need a browser
    # or a running server, so they are never used.
    NodeScriptProfile(
        name="juice-shop",
        markers=frozenset({"build:server", "test:server"}),
        build_script="build:server",
        test_script="test:server",
    ),
)


@dataclass(frozen=True)
class NodeScriptPlan:
    profile: str
    build_script: str | None
    test_script: str | None
    build_skip_reason: str | None = None
    test_skip_reason: str | None = None


def node_script_plan(scripts: Mapping[str, object]) -> NodeScriptPlan:
    """Which npm scripts validation runs for a package.json ``scripts`` table."""
    defined = {k for k, v in scripts.items() if isinstance(v, str) and v.strip()}
    for profile in NODE_SCRIPT_PROFILES:
        if profile.markers & defined:
            build = profile.build_script if profile.build_script in defined else None
            test = profile.test_script if profile.test_script in defined else None
            return NodeScriptPlan(
                profile=profile.name,
                build_script=build,
                test_script=test,
                build_skip_reason=None if build else f"no {profile.build_script} script",
                test_skip_reason=None if test else f"no tests found (no {profile.test_script})",
            )
    has_test = "test" in defined and str(scripts["test"]).strip() != NPM_DEFAULT_TEST
    return NodeScriptPlan(
        profile="generic",
        build_script=None,
        test_script="test" if has_test else None,
        build_skip_reason="no build:server script",
        test_skip_reason=None if has_test else "no tests found (no test script)",
    )


def _npm_command(script: str) -> list[str]:
    if script in NEVER_RUN_SCRIPTS:
        msg = f"Refusing to run npm script {script!r}"
        raise ValueError(msg)
    return [NPM, "test"] if script == "test" else [NPM, "run", script]


# --- logs -------------------------------------------------------------------------------


def write_log(log_dir: Path, step: str, text: str, cap_bytes: int) -> str:
    """Redact secrets, cap the size and write ``<log_dir>/<step>.log``; return its path."""
    redacted, _ = redact_secrets(text)
    raw = redacted.encode("utf-8", errors="replace")
    if len(raw) > cap_bytes:
        marker = f"\n[guardian: log truncated at {cap_bytes} bytes]\n".encode()
        raw = raw[: max(cap_bytes - len(marker), 0)] + marker
    log_dir.mkdir(parents=True, exist_ok=True)
    path = log_dir / f"{step}.log"
    path.write_bytes(raw)
    return str(path)


def _step(  # noqa: PLR0913 - keyword-only overrides of one step
    name: StepName,
    result: StepResult,
    log_path: str | None,
    *,
    detail: str | None = None,
    known_conflict: bool = False,
    status: StepStatus | None = None,
) -> ValidationStep:
    return ValidationStep(
        name=name,
        status=status or result.status,
        exit_code=result.exit_code,
        duration_seconds=round(result.duration_seconds, 3),
        log_path=log_path,
        detail=detail if detail is not None else result.detail,
        known_conflict=known_conflict,
    )


def _skipped(
    name: StepName, reason: str, status: StepStatus = StepStatus.SKIPPED
) -> ValidationStep:
    return ValidationStep(name=name, status=status, detail=reason)


# --- validation -------------------------------------------------------------------------


@dataclass
class _RunState:
    steps: list[ValidationStep]
    summary: TestSummary | None = None
    tests_discovered: int | None = None


def validate_case(  # noqa: PLR0913 - every collaborator is injectable for tests
    db: Database,
    case: RemediationCase,
    applied: AppliedChange,
    *,
    sandbox: Sandbox,
    config: SandboxConfig | None = None,
    unsafe_host: bool = False,
    host_sandbox: Sandbox | None = None,
    log_root: Path | None = None,
    actor: str = SYSTEM_ACTOR,
) -> ValidationRun:
    """Install, build and test ``applied`` in the sandbox; save and return the run."""
    config = config or sandbox.config
    started = datetime.now(UTC)
    run_id = f"{started.strftime('%Y%m%dT%H%M%SZ')}-{random_suffix()}"
    log_dir = (log_root or applied.worktree_path.parent.parent / "logs") / case.id / run_id
    db.audit.append(
        case.id,
        "validation:started",
        actor,
        {"branch": applied.branch, "commit": applied.commit_sha, "unsafe_host": unsafe_host},
    )

    ok, reason = sandbox.available()
    active: Sandbox | None = sandbox if ok else None
    if not ok and unsafe_host:
        host = host_sandbox or HostSandbox(config=config)
        host_ok, host_reason = host.available()
        if host_ok:
            active = host
        else:
            reason = f"{reason}; host validation unavailable: {host_reason}"

    if active is None:
        state = _RunState([_skipped(n, f"sandbox unavailable: {reason}") for n in STEP_NAMES])
        kind: Literal["docker", "none", "host-unsafe"] = "none"
    else:
        state = _run_steps(case, applied, active, config, log_dir)
        kind = active.kind

    summary = state.summary
    run = ValidationRun(
        case_id=case.id,
        branch=applied.branch,
        worktree_path=str(applied.worktree_path),
        commit_sha=applied.commit_sha,
        sandbox=kind,
        steps=state.steps,
        tests_discovered=state.tests_discovered,
        tests_passed=summary.passed if summary else None,
        tests_failed=summary.failed if summary else None,
        started_at=started,
        finished_at=datetime.now(UTC),
    )
    db.remediation.save_validation(run)
    db.audit.append(
        case.id,
        "validation:finished",
        actor,
        {
            "sandbox": run.sandbox,
            "steps": {s.name: s.status.value for s in run.steps},
            "tests_discovered": run.tests_discovered,
            "tests_failed": run.tests_failed,
        },
    )
    return run


def _run_steps(
    case: RemediationCase,
    applied: AppliedChange,
    sandbox: Sandbox,
    config: SandboxConfig,
    log_dir: Path,
) -> _RunState:
    worktree = applied.worktree_path
    package_json = read_regular_file(worktree / "package.json", config.max_manifest_bytes)
    if package_json is None:
        reason = "no package.json: only npm projects are validated"
        return _RunState([_skipped(n, reason) for n in STEP_NAMES])
    try:
        scripts = json.loads(package_json).get("scripts") or {}
    except (ValueError, UnicodeDecodeError, AttributeError):
        scripts = None
    if not isinstance(scripts, dict):
        reason = "package.json is not valid JSON or has an invalid scripts table"
        failed = _skipped("install", reason, StepStatus.FAILED)
        return _RunState([failed, *(_skipped(n, reason) for n in ("build", "test"))])
    plan = node_script_plan(scripts)

    work = make_work_dir(config, "guardian-validate-")
    try:
        deps, copy = work / "deps", work / "src"
        image, install = _install(case, worktree, sandbox, config, log_dir, deps, copy)
        steps = [install]
        if image is None:
            steps += [_skipped(n, "skipped: dependency install failed") for n in ("build", "test")]
            return _RunState(steps)
        build = _build(case, plan, image, copy, sandbox, config, log_dir)
        steps.append(build)
        if build.status not in {StepStatus.PASSED, StepStatus.SKIPPED}:
            steps.append(_skipped("test", f"skipped: build {build.status.value}"))
            return _RunState(steps)
        test, summary = _test(case, plan, image, copy, sandbox, config, log_dir)
        steps.append(test)
        discovered = summary.discovered if summary else None
        if test.status is StepStatus.NOT_FOUND:
            discovered = 0
        return _RunState(steps, summary, discovered)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _install(  # noqa: PLR0913, PLR0917 - internal step of _run_steps
    case: RemediationCase,
    worktree: Path,
    sandbox: Sandbox,
    config: SandboxConfig,
    log_dir: Path,
    deps: Path,
    copy: Path,
) -> tuple[str | None, ValidationStep]:
    lock = generate_npm_lockfile_step(
        worktree, deps, sandbox, name=container_name(case.id, "lockfile")
    )
    log_text = f"$ {' '.join(lock.step.argv)}\n{lock.step.output}"
    if lock.path is None:
        log = write_log(log_dir, "install", log_text, config.log_cap_bytes)
        status = lock.step.status
        if status in {StepStatus.PASSED, StepStatus.SKIPPED}:
            status = StepStatus.FAILED
        return None, _step("install", lock.step, log, detail=lock.warning, status=status)
    (deps / "package.json").write_bytes((worktree / "package.json").read_bytes())
    copy_tree(worktree, copy)
    (copy / LOCKFILE_NAME).write_bytes(lock.path.read_bytes())
    image, result = sandbox.install_dependencies(
        deps, copy, name=container_name(case.id, "install")
    )
    log_text += f"\n$ {' '.join(result.argv)}\n{result.output}"
    log = write_log(log_dir, "install", log_text, config.log_cap_bytes)
    total = StepResult(
        result.status,
        result.exit_code,
        lock.step.duration_seconds + result.duration_seconds,
        detail=result.detail,
    )
    return image, _step("install", total, log)


def _build(  # noqa: PLR0913, PLR0917 - internal step of _run_steps
    case: RemediationCase,
    plan: NodeScriptPlan,
    image: str,
    copy: Path,
    sandbox: Sandbox,
    config: SandboxConfig,
    log_dir: Path,
) -> ValidationStep:
    if plan.build_script is None:
        return _skipped("build", plan.build_skip_reason or "no build script")
    command = _npm_command(plan.build_script)
    result = sandbox.run(
        image,
        copy,
        command,
        network=False,
        timeout=config.step_timeout_seconds,
        name=container_name(case.id, "build"),
    )
    log = write_log(
        log_dir, "build", f"$ {' '.join(command)}\n{result.output}", config.log_cap_bytes
    )
    return _step("build", result, log, detail=result.detail or f"npm run {plan.build_script}")


def _test(  # noqa: PLR0913, PLR0917 - internal step of _run_steps
    case: RemediationCase,
    plan: NodeScriptPlan,
    image: str,
    copy: Path,
    sandbox: Sandbox,
    config: SandboxConfig,
    log_dir: Path,
) -> tuple[ValidationStep, TestSummary | None]:
    if plan.test_script is None:
        reason = plan.test_skip_reason or "no tests found"
        return _skipped("test", reason, StepStatus.NOT_FOUND), None
    command = _npm_command(plan.test_script)
    result = sandbox.run(
        image,
        copy,
        command,
        network=False,
        timeout=config.step_timeout_seconds,
        name=container_name(case.id, "test"),
    )
    log = write_log(
        log_dir, "test", f"$ {' '.join(command)}\n{result.output}", config.log_cap_bytes
    )
    summary = parse_node_test_output(result.output, roots=("/work", str(copy)))
    if result.status is StepStatus.TIMEOUT:
        return _step("test", result, log), summary
    if result.status is StepStatus.PASSED:
        if summary.discovered == 0:
            return _step(
                "test", result, log, detail="no tests found", status=StepStatus.NOT_FOUND
            ), summary
        counted = f"{summary.passed}/{summary.discovered} passed" if summary.discovered else None
        return _step("test", result, log, detail=counted or "tests passed"), summary
    if is_known_conflict(summary):
        names = ", ".join(Path(f).name for f in summary.failing_files)
        detail = f"{KNOWN_CONFLICT_DETAIL} ({names})"
        return _step("test", result, log, detail=detail, known_conflict=True), summary
    files = f": {', '.join(summary.failing_files)}" if summary.failing_files else ""
    failed = summary.failed if summary.failed is not None else "unknown number of"
    return _step("test", result, log, detail=f"{failed} failing test(s){files}"), summary

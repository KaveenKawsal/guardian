"""Sandboxes for running a repository's install, build and test commands (rule 9).

Running a repository's build or tests means running hostile code, so validation happens in a
Docker container that is as closed as Docker allows:

* ``--rm``, ``--user 1000:1000`` (the ``node`` user of the official node images),
  ``--cap-drop ALL``, ``--security-opt no-new-privileges``, ``--pids-limit``, ``--memory``,
  ``--cpus``, ``--read-only`` root filesystem with a ``tmpfs`` ``/tmp``;
* no host environment: only the fixed ``CONTAINER_ENV`` values are passed with ``--env``;
* the Docker socket is never mounted, and neither is the user's repository. The worktree is
  copied (without ``.git`` and ``node_modules``, never following symlinks) into a fresh,
  disposable temporary directory, and only that copy is bind-mounted read-write at ``/work``.
  A bind mount was chosen over ``docker create`` + ``docker cp`` because ``docker cp`` cannot
  write into a container whose root filesystem is ``--read-only``;
* phase 1 (lockfile regeneration, dependency image build) has network access, with install
  scripts disabled; phase 2 (build, tests) runs with ``--network none``;
* the container is named ``guardian-<case>-<step>``; on a wall-clock timeout it is
  ``docker kill``-ed (``--rm`` then removes it).

Every command is a fixed argument list; nothing is built from repository content.

Dependencies are preinstalled into a per-dependency-set image ``guardian-deps:<hash>`` built
from ``NODE_DEPS_DOCKERFILE`` (kept identical to ``docker/node24-deps.Dockerfile``). The image
installs into ``/deps/node_modules`` so the ``/work`` bind mount cannot hide it; the copy gets
a ``node_modules -> /deps/node_modules`` symlink written by Guardian.

``HostSandbox`` runs the same steps directly on the host. It exists only for the explicit
``--unsafe-host-validation`` opt-in, warns loudly, and its results are capped at
PARTIALLY_VERIFIED by ``verify``.
"""

import hashlib
import os
import shutil
import stat
import tempfile
import time
import uuid
import warnings
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol

from guardian.core.remediation_models import StepStatus
from guardian.execution.policies import DEFAULT_ENV_ALLOWLIST, ExecutionPolicy
from guardian.execution.results import ToolResult, ToolStatus
from guardian.execution.runner import ToolRunner

DOCKER = "docker"
NPM = "npm"
NODE = "node"
CONTAINER_UID = "1000:1000"
"""uid:gid of the ``node`` user in the official node images."""
WORKDIR = "/work"
DEPS_NODE_MODULES = "/deps/node_modules"
DEFAULT_COPY_EXCLUDES: frozenset[str] = frozenset({".git", "node_modules"})

CONTAINER_ENV: dict[str, str] = {
    "CI": "true",
    "NODE_ENV": "test",
    "npm_config_ignore_scripts": "true",
    "npm_config_audit": "false",
    "npm_config_fund": "false",
    "npm_config_update_notifier": "false",
    "HOME": "/tmp",  # noqa: S108 - the root filesystem is read-only; /tmp is the only writable tmpfs
    "npm_config_cache": f"{WORKDIR}/.guardian-npm-cache",  # on disk, not in tmpfs memory
}
"""The complete container environment. Nothing from the host is passed through."""

HOST_ENV: dict[str, str] = {
    "CI": "true",
    "NODE_ENV": "test",
    "npm_config_ignore_scripts": "true",
    "npm_config_audit": "false",
    "npm_config_fund": "false",
    "npm_config_update_notifier": "false",
}

# The docker CLI (not the container) needs these to find the daemon.
DOCKER_CLI_ENV_ALLOWLIST: frozenset[str] = DEFAULT_ENV_ALLOWLIST | frozenset(
    {"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY"}
)

NODE_DEPS_DOCKERFILE = """\
# Guardian dependency image: one image per (package.json, package-lock.json) pair.
# Built by guardian.remediation.sandbox.DockerSandbox.install_dependencies with a build context
# that contains only this file, package.json and package-lock.json.
FROM node:24-bookworm-slim
ENV CI=true \\
    NODE_ENV=test \\
    npm_config_ignore_scripts=true \\
    npm_config_audit=false \\
    npm_config_fund=false \\
    npm_config_update_notifier=false
RUN mkdir -p /deps /work && chown node:node /deps /work
USER node
WORKDIR /deps
COPY --chown=node:node package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund && npm cache clean --force
WORKDIR /work
"""

SandboxKind = Literal["docker", "host-unsafe"]


class UnsafeHostValidationWarning(UserWarning):
    """Repository code is about to run on the host without a sandbox."""


@dataclass(frozen=True)
class SandboxConfig:
    """Sandbox settings. Defaults match the Juice Shop demo; the integrator wires settings."""

    base_image: str = "node:24-bookworm-slim"
    deps_image_repository: str = "guardian-deps"
    cpus: str = "2"
    memory: str = "4g"
    pids_limit: int = 512
    tmpfs_size: str = "512m"
    install_timeout_seconds: float = 900.0
    step_timeout_seconds: float = 900.0
    log_cap_bytes: int = 2 * 1024 * 1024
    install_network: bool = True
    max_manifest_bytes: int = 5 * 1024 * 1024
    max_lockfile_bytes: int = 100 * 1024 * 1024
    work_root: Path | None = None
    """Parent directory for disposable copies; the system temp directory when None."""


@dataclass(frozen=True)
class StepResult:
    status: StepStatus
    exit_code: int | None = None
    duration_seconds: float = 0.0
    output: str = ""
    detail: str | None = None
    argv: tuple[str, ...] = field(default=())


class Sandbox(Protocol):
    kind: SandboxKind
    config: SandboxConfig

    def available(self) -> tuple[bool, str]: ...

    def run(  # noqa: PLR0913 - mirrors DockerSandbox.run
        self,
        image: str,
        workdir_copy: Path,
        command: Sequence[str],
        *,
        network: bool,
        timeout: float,
        name: str,
    ) -> StepResult: ...

    def install_dependencies(
        self, deps_dir: Path, work_copy: Path, *, name: str
    ) -> tuple[str | None, StepResult]: ...


# --- disposable copies ------------------------------------------------------------------


def make_work_dir(config: SandboxConfig, prefix: str) -> Path:
    """A fresh private (0700) temporary directory."""
    root = config.work_root
    if root is not None:
        root.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=prefix, dir=root))


def copy_tree(src: Path, dst: Path, *, exclude: frozenset[str] = DEFAULT_COPY_EXCLUDES) -> int:
    """Copy regular files and directories from ``src`` to ``dst``; return the file count.

    Symlinks, sockets and devices are skipped (never followed), files and directories
    named in ``exclude`` are skipped at any depth. Copies are made world-writable so the container's
    uid 1000 can write to them on Linux; they live inside a 0700 temporary directory.
    """
    count = 0
    dst.mkdir(parents=True, exist_ok=True)
    dst.chmod(0o777)
    for current, dirs, files in os.walk(src, followlinks=False):
        here = Path(current)
        rel = here.relative_to(src)
        kept = []
        for name in dirs:
            if name in exclude or (here / name).is_symlink():
                continue
            kept.append(name)
            target = dst / rel / name
            target.mkdir(exist_ok=True)
            target.chmod(0o777)
        dirs[:] = kept
        for name in files:
            if name in exclude:  # e.g. a worktree's `.git` is a file pointing at the repo
                continue
            path = here / name
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode):
                continue
            target = dst / rel / name
            shutil.copyfile(path, target, follow_symlinks=False)
            mode = 0o777 if info.st_mode & 0o111 else 0o666
            target.chmod(mode)
            count += 1
    return count


def read_regular_file(path: Path, max_bytes: int) -> bytes | None:
    """Bytes of a regular, non-symlink file no larger than ``max_bytes``; None otherwise."""
    try:
        info = path.lstat()
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_size > max_bytes:
        return None
    return path.read_bytes()


def deps_hash(package_json: bytes, lockfile: bytes) -> str:
    """First 12 hex characters of sha256(package.json + package-lock.json)."""
    digest = hashlib.sha256()
    digest.update(package_json)
    digest.update(b"\0")
    digest.update(lockfile)
    return digest.hexdigest()[:12]


def container_name(*parts: str) -> str:
    safe = "-".join(p for p in parts if p)
    cleaned = "".join(c if c.isalnum() or c in "_.-" else "-" for c in safe)
    return f"guardian-{cleaned}"[:120]


def random_suffix() -> str:
    return uuid.uuid4().hex[:8]


# --- docker -----------------------------------------------------------------------------


def sandbox_policy(config: SandboxConfig) -> ExecutionPolicy:
    """Runner policy for the docker CLI: git + docker only, bounded output."""
    return ExecutionPolicy(
        allowed_tools=frozenset({"git", DOCKER}),
        timeout_seconds=config.step_timeout_seconds,
        max_output_bytes=config.log_cap_bytes,
        env_allowlist=DOCKER_CLI_ENV_ALLOWLIST,
    )


def docker_run_args(  # noqa: PLR0913 - every argument is a security-relevant knob
    config: SandboxConfig,
    *,
    image: str,
    workdir_copy: Path,
    command: Sequence[str],
    network: bool,
    name: str,
) -> list[str]:
    """The exact ``docker run`` argument list (without the ``docker`` executable)."""
    src = str(workdir_copy.resolve())
    if "," in src or "=" in src:
        msg = f"Refusing to bind-mount a path containing ',' or '=': {src}"
        raise ValueError(msg)
    args = [
        "run",
        "--rm",
        "--name",
        name,
        "--user",
        CONTAINER_UID,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        str(config.pids_limit),
        "--memory",
        config.memory,
        "--cpus",
        config.cpus,
        "--read-only",
        "--tmpfs",
        f"/tmp:rw,noexec,nosuid,nodev,size={config.tmpfs_size}",  # noqa: S108 - in-container
        "--network",
        "bridge" if network else "none",
    ]
    for key, value in CONTAINER_ENV.items():
        args += ["--env", f"{key}={value}"]
    args += [
        "--mount",
        f"type=bind,src={src},dst={WORKDIR}",
        "--workdir",
        WORKDIR,
        image,
        *command,
    ]
    return args


def _combined_output(result: ToolResult) -> str:
    parts = [result.stdout, result.stderr]
    if result.error:
        parts.append(result.error)
    return "\n".join(p for p in parts if p)


def _step_from_result(result: ToolResult, argv: Sequence[str]) -> StepResult:
    output = _combined_output(result)
    if result.status is ToolStatus.TIMEOUT:
        return StepResult(
            StepStatus.TIMEOUT,
            None,
            result.duration_seconds,
            output,
            result.error,
            tuple(argv),
        )
    if result.status in {ToolStatus.NOT_FOUND, ToolStatus.ERROR}:
        return StepResult(
            StepStatus.FAILED, None, result.duration_seconds, output, result.error, tuple(argv)
        )
    status = StepStatus.PASSED if result.ok else StepStatus.FAILED
    return StepResult(status, result.exit_code, result.duration_seconds, output, None, tuple(argv))


class DockerSandbox:
    kind: SandboxKind = "docker"

    def __init__(
        self, runner: ToolRunner | None = None, config: SandboxConfig | None = None
    ) -> None:
        self.config = config or SandboxConfig()
        self.runner = runner or ToolRunner(sandbox_policy(self.config))

    def available(self) -> tuple[bool, str]:
        """Docker is usable only when the CLI exists and the daemon answers ``docker info``."""
        if not self.runner.is_available(DOCKER):
            return False, "docker CLI not found on PATH"
        info = self.runner.run(
            DOCKER,
            ["info", "--format", "{{.ServerVersion}}"],
            cwd=Path.cwd(),
            timeout_seconds=30,
        )
        if not info.ok:
            detail = (info.stderr or info.error or "").strip().splitlines()
            return False, f"docker daemon not reachable ({detail[0] if detail else 'no output'})"
        return True, f"docker {info.stdout.strip()}"

    def run(  # noqa: PLR0913 - see Sandbox.run
        self,
        image: str,
        workdir_copy: Path,
        command: Sequence[str],
        *,
        network: bool,
        timeout: float,
        name: str,
    ) -> StepResult:
        args = docker_run_args(
            self.config,
            image=image,
            workdir_copy=workdir_copy,
            command=command,
            network=network,
            name=name,
        )
        # A stale container from a crashed run would make `docker run --name` fail.
        self.runner.run(DOCKER, ["rm", "--force", name], cwd=workdir_copy, timeout_seconds=60)
        result = self.runner.run(DOCKER, args, cwd=workdir_copy, timeout_seconds=timeout)
        if result.status is ToolStatus.TIMEOUT:
            self.runner.run(DOCKER, ["kill", name], cwd=workdir_copy, timeout_seconds=60)
        return _step_from_result(result, [DOCKER, *args])

    def image_exists(self, tag: str) -> bool:
        result = self.runner.run(
            DOCKER, ["image", "inspect", "--format", "{{.Id}}", tag], cwd=Path.cwd()
        )
        return result.ok

    def install_dependencies(
        self, deps_dir: Path, work_copy: Path, *, name: str
    ) -> tuple[str | None, StepResult]:
        """Build (or reuse) ``guardian-deps:<hash>`` from ``deps_dir``'s package.json and
        package-lock.json, and link ``work_copy/node_modules`` to the image's modules."""
        cfg = self.config
        package_json = read_regular_file(deps_dir / "package.json", cfg.max_manifest_bytes)
        lockfile = read_regular_file(deps_dir / "package-lock.json", cfg.max_lockfile_bytes)
        if package_json is None or lockfile is None:
            return None, StepResult(StepStatus.FAILED, detail="package.json or lockfile missing")
        tag = f"{cfg.deps_image_repository}:{deps_hash(package_json, lockfile)}"
        if self.image_exists(tag):
            _link_node_modules(work_copy)
            return tag, StepResult(StepStatus.PASSED, 0, detail=f"reused dependency image {tag}")

        context = make_work_dir(cfg, "guardian-deps-ctx-")
        try:
            (context / "package.json").write_bytes(package_json)
            (context / "package-lock.json").write_bytes(lockfile)
            (context / "Dockerfile").write_text(NODE_DEPS_DOCKERFILE, encoding="utf-8")
            args = [
                "build",
                "--tag",
                tag,
                "--label",
                f"guardian.deps-hash={tag.rsplit(':', 1)[1]}",
                "--network",
                "default" if cfg.install_network else "none",
                "--file",
                str(context / "Dockerfile"),
                str(context),
            ]
            result = self.runner.run(
                DOCKER, args, cwd=context, timeout_seconds=cfg.install_timeout_seconds
            )
        finally:
            shutil.rmtree(context, ignore_errors=True)
        step = _step_from_result(result, [DOCKER, *args])
        if step.status is not StepStatus.PASSED:
            return None, step
        _link_node_modules(work_copy)
        detail = f"built dependency image {tag} for {name}"
        return tag, StepResult(
            step.status, step.exit_code, step.duration_seconds, step.output, detail, step.argv
        )


def _link_node_modules(work_copy: Path) -> None:
    link = work_copy / "node_modules"
    if link.is_symlink() or link.exists():
        if link.is_dir() and not link.is_symlink():
            shutil.rmtree(link)
        else:
            link.unlink()
    link.symlink_to(DEPS_NODE_MODULES)


# --- host (unsafe) ----------------------------------------------------------------------


def host_policy(config: SandboxConfig) -> ExecutionPolicy:
    return ExecutionPolicy(
        allowed_tools=frozenset({NPM, NODE}),
        timeout_seconds=config.step_timeout_seconds,
        max_output_bytes=config.log_cap_bytes,
        extra_env=HOST_ENV,
    )


UNSAFE_HOST_WARNING = (
    "UNSAFE: --unsafe-host-validation runs the repository's install, build and test commands "
    "directly on this machine, without a sandbox. Hostile code in the repository can read "
    "your files and credentials. The verdict is capped at PARTIALLY_VERIFIED."
)


class HostSandbox:
    """Runs the same commands on the host. Only for the explicit unsafe opt-in."""

    kind: SandboxKind = "host-unsafe"

    def __init__(
        self, runner: ToolRunner | None = None, config: SandboxConfig | None = None
    ) -> None:
        self.config = config or SandboxConfig()
        self.runner = runner or ToolRunner(host_policy(self.config))
        self._warned = False

    def warn(self) -> None:
        if not self._warned:
            warnings.warn(UNSAFE_HOST_WARNING, UnsafeHostValidationWarning, stacklevel=3)
            self._warned = True

    def available(self) -> tuple[bool, str]:
        if not self.runner.is_available(NPM):
            return False, "npm not found on PATH"
        return True, "host (unsafe, no isolation)"

    def run(  # noqa: PLR0913 - see Sandbox.run
        self,
        image: str,  # noqa: ARG002 - the host has no images
        workdir_copy: Path,
        command: Sequence[str],
        *,
        network: bool,  # noqa: ARG002 - the host cannot disable networking per command
        timeout: float,
        name: str,  # noqa: ARG002 - no container to name
    ) -> StepResult:
        self.warn()
        tool, *args = command
        result = self.runner.run(tool, args, cwd=workdir_copy, timeout_seconds=timeout)
        return _step_from_result(result, command)

    def install_dependencies(
        self, deps_dir: Path, work_copy: Path, *, name: str
    ) -> tuple[str | None, StepResult]:
        lockfile = deps_dir / "package-lock.json"
        if read_regular_file(lockfile, self.config.max_lockfile_bytes) is None:
            return None, StepResult(StepStatus.FAILED, detail="lockfile missing")
        shutil.copyfile(lockfile, work_copy / "package-lock.json")
        started = time.monotonic()
        step = self.run(
            "",
            work_copy,
            [NPM, "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
            network=True,
            timeout=self.config.install_timeout_seconds,
            name=name,
        )
        if step.status is not StepStatus.PASSED:
            return None, step
        detail = "npm ci --ignore-scripts on the host"
        elapsed = time.monotonic() - started
        return "host", StepResult(
            step.status, step.exit_code, elapsed, step.output, detail, step.argv
        )

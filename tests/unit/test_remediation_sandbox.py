# ruff: noqa: SLF001 - toggles the warn-once flag
from pathlib import Path

import pytest
from remediation_fakes import FakeRunner, ok

from guardian.core.remediation_models import StepStatus
from guardian.execution.results import ToolResult, ToolStatus
from guardian.remediation import sandbox as sandbox_module
from guardian.remediation.lockfile import (
    NPM_LOCKFILE_COMMAND,
    generate_npm_lockfile,
    generate_npm_lockfile_step,
)
from guardian.remediation.sandbox import (
    CONTAINER_ENV,
    NODE_DEPS_DOCKERFILE,
    DockerSandbox,
    HostSandbox,
    SandboxConfig,
    StepResult,
    UnsafeHostValidationWarning,
    container_name,
    copy_tree,
    deps_hash,
    docker_run_args,
    host_policy,
    read_regular_file,
    sandbox_policy,
)

REPO_ROOT = Path(__file__).parents[2]


@pytest.fixture
def config(tmp_path):
    return SandboxConfig(work_root=tmp_path / "work")


def test_docker_run_args_are_locked_down(tmp_path, config):
    copy = tmp_path / "copy"
    copy.mkdir()
    args = docker_run_args(
        config,
        image="guardian-deps:abc",
        workdir_copy=copy,
        command=["npm", "run", "test:server"],
        network=False,
        name="guardian-rc_1-test",
    )
    env = [f"{k}={v}" for k, v in CONTAINER_ENV.items()]
    expected = [
        "run",
        "--rm",
        "--name",
        "guardian-rc_1-test",
        "--user",
        "1000:1000",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "512",
        "--memory",
        "4g",
        "--cpus",
        "2",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=512m",
        "--network",
        "none",
        *[a for kv in env for a in ("--env", kv)],
        "--mount",
        f"type=bind,src={copy.resolve()},dst=/work",
        "--workdir",
        "/work",
        "guardian-deps:abc",
        "npm",
        "run",
        "test:server",
    ]
    assert args == expected
    joined = " ".join(args)
    assert "docker.sock" not in joined
    assert "-v" not in args
    assert "--privileged" not in args
    # Only the fixed, safe variables reach the container; nothing from the host.
    env_values = [args[i + 1] for i, a in enumerate(args) if a == "--env"]
    assert {e.split("=", 1)[0] for e in env_values} == set(CONTAINER_ENV)
    assert "PATH" not in CONTAINER_ENV
    assert CONTAINER_ENV["npm_config_ignore_scripts"] == "true"


def test_install_phase_has_network(tmp_path, config):
    args = docker_run_args(
        config,
        image="node:24-bookworm-slim",
        workdir_copy=tmp_path,
        command=list(NPM_LOCKFILE_COMMAND),
        network=True,
        name="n",
    )
    assert args[args.index("--network") + 1] == "bridge"


def test_bind_mount_refuses_comma_paths(tmp_path, config):
    bad = tmp_path / "a,b"
    bad.mkdir()
    with pytest.raises(ValueError, match="Refusing"):
        docker_run_args(config, image="i", workdir_copy=bad, command=["x"], network=False, name="n")


def test_run_removes_stale_container_and_runs(tmp_path, config):
    runner = FakeRunner()
    result = DockerSandbox(runner, config).run(
        "img", tmp_path, ["npm", "run", "build:server"], network=False, timeout=12, name="c1"
    )
    assert result.status is StepStatus.PASSED
    assert result.exit_code == 0
    assert runner.calls[0][:2] == ("docker", ["rm", "--force", "c1"])
    tool, args, _, timeout = runner.calls[1]
    assert tool == "docker"
    assert args[0] == "run"
    assert timeout == 12
    assert result.argv[0] == "docker"


def test_timeout_kills_container(tmp_path, config):
    def handler(tool, args, cwd):
        if args[0] == "run":
            return ToolResult(tool=tool, args=args, status=ToolStatus.TIMEOUT, error="timed out")
        return ok(tool, args)

    runner = FakeRunner(handler)
    result = DockerSandbox(runner, config).run(
        "img", tmp_path, ["npm", "test"], network=False, timeout=1, name="c2"
    )
    assert result.status is StepStatus.TIMEOUT
    assert runner.calls[-1][1] == ["kill", "c2"]


def test_failed_and_unstartable_commands(tmp_path, config):
    def failing(tool, args, cwd):
        if args[0] == "run":
            return ok(tool, args, stdout="boom", exit_code=2)
        return ok(tool, args)

    result = DockerSandbox(FakeRunner(failing), config).run(
        "img", tmp_path, ["npm", "test"], network=False, timeout=1, name="c"
    )
    assert (result.status, result.exit_code, result.output) == (StepStatus.FAILED, 2, "boom")

    def missing(tool, args, cwd):
        return ToolResult(tool=tool, args=args, status=ToolStatus.NOT_FOUND, error="nope")

    result = DockerSandbox(FakeRunner(missing), config).run(
        "img", tmp_path, ["npm", "test"], network=False, timeout=1, name="c"
    )
    assert result.status is StepStatus.FAILED
    assert result.detail == "nope"


def test_available_requires_cli_and_daemon(config):
    no_cli = DockerSandbox(FakeRunner(available=frozenset()), config)
    assert no_cli.available() == (False, "docker CLI not found on PATH")

    def down(tool, args, cwd):
        return ToolResult(
            tool=tool, args=args, status=ToolStatus.FAILED, exit_code=1, stderr="Cannot connect"
        )

    ok_flag, reason = DockerSandbox(FakeRunner(down), config).available()
    assert not ok_flag
    assert "Cannot connect" in reason

    up = DockerSandbox(FakeRunner(lambda t, a, c: ok(t, a, stdout="27.1.1\n")), config)
    assert up.available() == (True, "docker 27.1.1")


def test_sandbox_policy_allows_only_git_and_docker(config):
    policy = sandbox_policy(config)
    assert policy.allowed_tools == frozenset({"git", "docker"})
    assert policy.max_output_bytes == config.log_cap_bytes
    env = policy.build_env({"PATH": "/bin", "JIRA_API_TOKEN": "x", "DOCKER_HOST": "unix:///s"})
    assert env == {"PATH": "/bin", "DOCKER_HOST": "unix:///s"}
    assert host_policy(config).allowed_tools == frozenset({"npm", "node"})


def _deps_dir(tmp_path) -> Path:
    deps = tmp_path / "deps"
    deps.mkdir()
    (deps / "package.json").write_text('{"name": "app"}')
    (deps / "package-lock.json").write_text('{"lockfileVersion": 3}')
    return deps


def test_install_dependencies_reuses_existing_image(tmp_path, config):
    deps, copy = _deps_dir(tmp_path), tmp_path / "copy"
    copy.mkdir()
    (copy / "node_modules").mkdir()  # never trusted: replaced by the link
    runner = FakeRunner()
    image, step = DockerSandbox(runner, config).install_dependencies(deps, copy, name="x")
    digest = deps_hash(b'{"name": "app"}', b'{"lockfileVersion": 3}')
    assert image == f"guardian-deps:{digest}"
    assert step.status is StepStatus.PASSED
    assert "reused" in step.detail
    assert [c[1][0] for c in runner.calls] == ["image"]
    assert (copy / "node_modules").readlink() == Path("/deps/node_modules")


def test_install_dependencies_builds_image_from_minimal_context(tmp_path, config):
    deps, copy = _deps_dir(tmp_path), tmp_path / "copy"
    copy.mkdir()
    seen = {}

    def handler(tool, args, cwd):
        if args[0] == "image":
            return ok(tool, args, exit_code=1)
        if args[0] == "build":
            context = Path(args[-1])
            seen["files"] = sorted(p.name for p in context.iterdir())
            seen["dockerfile"] = (context / "Dockerfile").read_text()
            seen["args"] = args
        return ok(tool, args)

    image, step = DockerSandbox(FakeRunner(handler), config).install_dependencies(
        deps, copy, name="x"
    )
    assert image is not None
    assert image.startswith("guardian-deps:")
    assert step.status is StepStatus.PASSED
    assert seen["files"] == ["Dockerfile", "package-lock.json", "package.json"]
    assert seen["dockerfile"] == NODE_DEPS_DOCKERFILE
    assert seen["args"][:3] == ["build", "--tag", image]
    assert "--network" in seen["args"]
    assert (copy / "node_modules").is_symlink()


def test_install_dependencies_failures(tmp_path, config):
    copy = tmp_path / "copy"
    copy.mkdir()
    empty = tmp_path / "empty"
    empty.mkdir()
    image, step = DockerSandbox(FakeRunner(), config).install_dependencies(empty, copy, name="x")
    assert image is None
    assert step.status is StepStatus.FAILED

    def build_fails(tool, args, cwd):
        return ok(tool, args, exit_code=1)

    deps = _deps_dir(tmp_path)
    image, step = DockerSandbox(FakeRunner(build_fails), config).install_dependencies(
        deps, copy, name="x"
    )
    assert image is None
    assert step.status is StepStatus.FAILED


def test_dockerfile_matches_repository_copy():
    text = (REPO_ROOT / "docker" / "node24-deps.Dockerfile").read_text(encoding="utf-8")
    assert text == NODE_DEPS_DOCKERFILE
    assert "FROM node:24-bookworm-slim" in text
    assert "USER node" in text
    assert "npm ci --ignore-scripts" in text


def test_copy_tree_skips_git_node_modules_and_symlinks(tmp_path):
    src = tmp_path / "src"
    (src / ".git").mkdir(parents=True)
    (src / ".git" / "config").write_text("x")
    (src / "node_modules" / "a").mkdir(parents=True)
    (src / "lib").mkdir()
    (src / "lib" / "a.ts").write_text("a")
    (src / "run.sh").write_text("#!/bin/sh")
    (src / "run.sh").chmod(0o755)
    outside = tmp_path / "secret.txt"
    outside.write_text("secret")
    (src / "leak.txt").symlink_to(outside)
    (src / "leakdir").symlink_to(tmp_path)
    count = copy_tree(src, tmp_path / "dst")
    dst = tmp_path / "dst"
    assert count == 2
    assert sorted(p.name for p in dst.iterdir()) == ["lib", "run.sh"]
    assert (dst / "lib" / "a.ts").read_text() == "a"
    assert (dst / "run.sh").stat().st_mode & 0o777 == 0o777
    assert (dst / "lib" / "a.ts").stat().st_mode & 0o777 == 0o666


def test_read_regular_file_limits(tmp_path):
    f = tmp_path / "f"
    f.write_bytes(b"12345")
    assert read_regular_file(f, 10) == b"12345"
    assert read_regular_file(f, 2) is None
    assert read_regular_file(tmp_path / "missing", 10) is None
    (tmp_path / "link").symlink_to(f)
    assert read_regular_file(tmp_path / "link", 10) is None


def test_container_name_is_sanitized():
    assert container_name("rc_1", "te st/../x") == "guardian-rc_1-te-st-..-x"


def test_host_sandbox_warns_loudly(tmp_path, config):
    runner = FakeRunner(available=frozenset({"npm"}))
    host = HostSandbox(runner, config)
    assert host.available() == (True, "host (unsafe, no isolation)")
    with pytest.warns(UnsafeHostValidationWarning, match="UNSAFE"):
        result = host.run("ignored", tmp_path, ["npm", "test"], network=False, timeout=5, name="n")
    assert result.status is StepStatus.PASSED
    assert runner.calls[0][:2] == ("npm", ["test"])
    assert HostSandbox(FakeRunner(available=frozenset()), config).available()[0] is False


def test_host_install_dependencies(tmp_path, config):
    deps, copy = _deps_dir(tmp_path), tmp_path / "copy"
    copy.mkdir()
    host = HostSandbox(FakeRunner(), config)
    with pytest.warns(UnsafeHostValidationWarning):
        image, step = host.install_dependencies(deps, copy, name="n")
    assert image == "host"
    assert (copy / "package-lock.json").is_file()
    assert step.detail == "npm ci --ignore-scripts on the host"

    failing = HostSandbox(FakeRunner(lambda t, a, c: ok(t, a, exit_code=1)), config)
    failing._warned = True
    assert failing.install_dependencies(deps, copy, name="n")[0] is None
    assert host.install_dependencies(tmp_path / "copy" / "nope", copy, name="n")[0] is None


# --- lockfile -----------------------------------------------------------------------------


class LockSandbox:
    kind = "docker"

    def __init__(self, config, *, available=(True, "ok"), status=StepStatus.PASSED, write=True):
        self.config = config
        self._available = available
        self.status = status
        self.write = write
        self.seen: dict = {}

    def available(self):
        return self._available

    def run(self, image, workdir_copy, command, *, network, timeout, name):
        self.seen = {
            "image": image,
            "files": sorted(p.name for p in workdir_copy.iterdir()),
            "command": list(command),
            "network": network,
            "name": name,
        }
        if self.write:
            (workdir_copy / "package-lock.json").write_text('{"lockfileVersion": 3}')
        return StepResult(self.status, 0 if self.status is StepStatus.PASSED else 1)


def test_lockfile_written_only_to_out_dir(tmp_path, config):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text('{"name": "juice-shop"}')
    (repo / ".npmrc").write_text("package-lock=false\nregistry=https://evil.example\n")
    before = sorted(p.name for p in repo.iterdir())
    sandbox = LockSandbox(config)
    path, warning = generate_npm_lockfile(repo, tmp_path / "out", sandbox)
    assert warning is None
    assert path == tmp_path / "out" / "package-lock.json"
    assert path.read_text() == '{"lockfileVersion": 3}'
    assert sorted(p.name for p in repo.iterdir()) == before  # user's repo untouched
    assert sandbox.seen["files"] == ["package.json"]  # no .npmrc in the sandbox copy
    assert sandbox.seen["command"] == [
        "npm",
        "install",
        "--package-lock-only",
        "--package-lock=true",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
    ]
    assert sandbox.seen["network"] is True
    assert sandbox.seen["image"] == "node:24-bookworm-slim"
    assert not list((tmp_path / "work").iterdir())  # disposable copy removed


def test_lockfile_keeps_existing_lockfile_pins(tmp_path, config):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text("{}")
    (repo / "package-lock.json").write_text('{"old": true}')
    sandbox = LockSandbox(config, write=False)
    outcome = generate_npm_lockfile_step(repo, tmp_path / "out", sandbox, name="x")
    assert sandbox.seen["files"] == ["package-lock.json", "package.json"]
    assert outcome.path is not None
    assert outcome.path.read_text() == '{"old": true}'


@pytest.mark.parametrize(
    ("setup", "sandbox_kwargs", "expected"),
    [
        ("{}", {"available": (False, "docker daemon not reachable")}, "sandbox unavailable"),
        (None, {}, "no readable package.json"),
        ("{not json", {}, "not valid JSON"),
        ("{}", {"status": StepStatus.FAILED}, "npm lockfile generation failed (failed, exit 1)"),
        ("{}", {"write": False}, "produced no usable package-lock.json"),
    ],
)
def test_lockfile_failures_warn(tmp_path, config, setup, sandbox_kwargs, expected):
    repo = tmp_path / "repo"
    repo.mkdir()
    if setup is not None:
        (repo / "package.json").write_text(setup)
    path, warning = generate_npm_lockfile(
        repo, tmp_path / "out", LockSandbox(config, **sandbox_kwargs)
    )
    assert path is None
    assert expected in warning
    assert not (tmp_path / "out").exists()


def test_work_dir_defaults_to_system_temp(monkeypatch, tmp_path):
    created = sandbox_module.make_work_dir(SandboxConfig(), "guardian-test-")
    try:
        assert created.is_dir()
        assert created.stat().st_mode & 0o777 == 0o700
    finally:
        created.rmdir()

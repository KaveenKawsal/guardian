# ruff: noqa: RUF001, S105 - U+2139 is real node reporter output; SPEC_PASS is not a secret
import json
from pathlib import Path

import pytest
from remediation_fakes import FakeRunner, FakeSandbox, make_case, make_scan, ok

from guardian.core.remediation_models import StepStatus
from guardian.remediation.apply import AppliedChange
from guardian.remediation.sandbox import (
    HostSandbox,
    SandboxConfig,
    StepResult,
    UnsafeHostValidationWarning,
)
from guardian.remediation.validate import (
    _npm_command,
    node_script_plan,
    validate_case,
    write_log,
)
from guardian.storage.database import Database

JUICE_SCRIPTS = {
    "postinstall": "cd frontend && npm install && npm run build",
    "build:server": "tsc",
    "test": "npm run test:server && npm run test:frontend",
    "test:server": "node --import ./test/server/helpers/test-env.mjs --import tsx --test x",
    "test:frontend": "ng test",
    "test:api": "jest",
}
SPEC_PASS = "ℹ tests 3\nℹ pass 3\nℹ fail 0\n"
SPEC_RSN = "test at test/server/rsn.unit.test.ts:4:1\n✖ rsn check\nℹ tests 3\nℹ pass 2\nℹ fail 1\n"
SPEC_REAL = "test at test/server/verify.unit.test.ts:4:1\nℹ tests 3\nℹ pass 2\nℹ fail 1\n"
TOKEN = "ghp_" + "a" * 36


@pytest.fixture
def env(tmp_path):
    home = tmp_path / "home"
    worktree = home / "worktrees" / "rc_x"
    worktree.mkdir(parents=True)
    (worktree / ".git").write_text("gitdir: elsewhere")
    with Database(tmp_path / "guardian.db") as db:
        make_scan(db, "before", "/repo")
        case = make_case(db, "/repo")
        applied = AppliedChange(
            case_id=case.id,
            branch=f"guardian/fix-{case.id}",
            worktree_path=worktree,
            commit_sha="abc123",
            base_commit="def456",
            changed_paths=["package.json"],
        )
        yield {"db": db, "case": case, "applied": applied, "worktree": worktree, "home": home}


def _package(env, scripts, raw=None):
    text = raw if raw is not None else json.dumps({"name": "app", "scripts": scripts})
    (env["worktree"] / "package.json").write_text(text)


def _validate(env, sandbox, **kwargs):
    return validate_case(env["db"], env["case"], env["applied"], sandbox=sandbox, **kwargs)


def test_juice_shop_install_build_test(env):
    _package(env, JUICE_SCRIPTS)
    (env["worktree"] / "lib").mkdir()
    (env["worktree"] / "lib" / "insecurity.ts").write_text("x")
    sandbox = FakeSandbox(
        results={
            "build": StepResult(StepStatus.PASSED, 0, 1.5, f"tsc ok token={TOKEN}"),
            "test": StepResult(StepStatus.PASSED, 0, 3.0, SPEC_PASS),
        }
    )
    run = _validate(env, sandbox)

    assert run.sandbox == "docker"
    assert [(s.name, s.status) for s in run.steps] == [
        ("install", StepStatus.PASSED),
        ("build", StepStatus.PASSED),
        ("test", StepStatus.PASSED),
    ]
    assert (run.tests_discovered, run.tests_passed, run.tests_failed) == (3, 3, 0)
    assert run.commit_sha == "abc123"

    lock, build, test = sandbox.runs
    assert lock["command"][:3] == ["npm", "install", "--package-lock-only"]
    assert lock["network"] is True
    assert lock["files"] == ["package.json"]
    assert build["command"] == ["npm", "run", "build:server"]
    assert test["command"] == ["npm", "run", "test:server"]
    assert build["network"] is False
    assert test["network"] is False
    assert build["image"] == test["image"] == "guardian-deps:0123456789ab"
    assert build["name"] == f"guardian-{env['case'].id}-build"
    assert ".git" not in build["files"]
    assert "lib" in build["files"]
    assert sandbox.installs[0]["deps"] == ["package-lock.json", "package.json"]
    assert all("postinstall" not in r["command"] for r in sandbox.runs)

    # Logs: per step, under <home>/logs/<case>/<run>/, secrets redacted.
    build_log = Path(run.steps[1].log_path)
    assert build_log.parent.parent == env["home"] / "logs" / env["case"].id
    assert TOKEN not in build_log.read_text()
    assert "[REDACTED]" in build_log.read_text()
    assert env["db"].remediation.validations(env["case"].id) == [run]
    events = [e.event for e in env["db"].audit.list(env["case"].id)]
    assert events[-2:] == ["validation:started", "validation:finished"]


def test_no_docker_skips_everything(env):
    _package(env, JUICE_SCRIPTS)
    sandbox = FakeSandbox(available=(False, "docker daemon not reachable"))
    run = _validate(env, sandbox)
    assert run.sandbox == "none"
    assert {s.status for s in run.steps} == {StepStatus.SKIPPED}
    assert run.steps[0].detail == "sandbox unavailable: docker daemon not reachable"
    assert sandbox.runs == []


def test_unsafe_host_runs_on_host_with_warning(env):
    _package(env, JUICE_SCRIPTS)

    def handler(tool, args, cwd):
        if args[:1] == ["install"]:
            (cwd / "package-lock.json").write_text("{}")
        if args == ["run", "test:server"]:
            return ok(tool, args, stdout=SPEC_PASS)
        return ok(tool, args)

    runner = FakeRunner(handler, available=frozenset({"npm"}))
    host = HostSandbox(runner, SandboxConfig())
    with pytest.warns(UnsafeHostValidationWarning):
        run = _validate(env, FakeSandbox(available=(False, "no docker")), unsafe_host=True,
                        host_sandbox=host)  # fmt: skip
    assert run.sandbox == "host-unsafe"
    assert [s.status for s in run.steps] == [StepStatus.PASSED] * 3
    commands = [(tool, args[:2]) for tool, args, *_ in runner.calls]
    assert ("npm", ["ci", "--ignore-scripts"]) in commands
    assert ("npm", ["run", "build:server"]) in commands


def test_unsafe_host_without_npm_stays_unavailable(env):
    _package(env, JUICE_SCRIPTS)
    host = HostSandbox(FakeRunner(available=frozenset()), SandboxConfig())
    run = _validate(env, FakeSandbox(available=(False, "no docker")), unsafe_host=True,
                    host_sandbox=host)  # fmt: skip
    assert run.sandbox == "none"
    assert "host validation unavailable" in run.steps[0].detail


def test_rsn_only_failures_are_known_conflicts(env):
    _package(env, JUICE_SCRIPTS)
    sandbox = FakeSandbox(results={"test": StepResult(StepStatus.FAILED, 1, 1.0, SPEC_RSN)})
    test = _validate(env, sandbox).steps[2]
    assert test.status is StepStatus.FAILED
    assert test.known_conflict
    assert test.detail == "fix conflicts with intentional challenge code (rsn.unit.test.ts)"


def test_real_test_failures(env):
    _package(env, JUICE_SCRIPTS)
    sandbox = FakeSandbox(results={"test": StepResult(StepStatus.FAILED, 1, 1.0, SPEC_REAL)})
    run = _validate(env, sandbox)
    assert not run.steps[2].known_conflict
    assert run.steps[2].detail == "1 failing test(s): test/server/verify.unit.test.ts"
    assert run.tests_failed == 1

    crash = FakeSandbox(results={"test": StepResult(StepStatus.FAILED, 1, 1.0, "Segfault")})
    assert _validate(env, crash).steps[2].detail == "unknown number of failing test(s)"


def test_zero_tests_and_timeouts(env):
    _package(env, JUICE_SCRIPTS)
    zero = FakeSandbox(results={"test": StepResult(StepStatus.PASSED, 0, 1, "ℹ tests 0\n")})
    run = _validate(env, zero)
    assert run.steps[2].status is StepStatus.NOT_FOUND
    assert run.tests_discovered == 0

    no_count = FakeSandbox(results={"test": StepResult(StepStatus.PASSED, 0, 1, "done")})
    run = _validate(env, no_count)
    assert run.steps[2].detail == "tests passed"
    assert run.tests_discovered is None

    slow = FakeSandbox(results={"test": StepResult(StepStatus.TIMEOUT, None, 900, "")})
    assert _validate(env, slow).steps[2].status is StepStatus.TIMEOUT


def test_build_failure_skips_tests(env):
    _package(env, JUICE_SCRIPTS)
    sandbox = FakeSandbox(results={"build": StepResult(StepStatus.FAILED, 2, 1, "TS2345")})
    run = _validate(env, sandbox)
    assert run.steps[1].status is StepStatus.FAILED
    assert run.steps[2].status is StepStatus.SKIPPED
    assert run.steps[2].detail == "skipped: build failed"


def test_install_failures(env):
    _package(env, JUICE_SCRIPTS)
    no_lock = FakeSandbox(lockfile=None)
    run = _validate(env, no_lock)
    assert run.steps[0].status is StepStatus.FAILED
    assert "no usable package-lock.json" in run.steps[0].detail
    assert run.steps[1].detail == "skipped: dependency install failed"

    image_fails = FakeSandbox(results={"install": StepResult(StepStatus.FAILED, 1, 1, "E404")})
    run = _validate(env, image_fails)
    assert run.steps[0].status is StepStatus.FAILED
    assert "E404" in Path(run.steps[0].log_path).read_text()


def test_generic_project_and_missing_tests(env):
    _package(env, {"test": "mocha"})
    sandbox = FakeSandbox(results={"test": StepResult(StepStatus.PASSED, 0, 1, "# tests 2\n")})
    run = _validate(env, sandbox)
    assert run.steps[1].status is StepStatus.SKIPPED
    assert run.steps[1].detail == "no build:server script"
    assert sandbox.runs[-1]["command"] == ["npm", "test"]

    _package(env, {"test": 'echo "Error: no test specified" && exit 1'})
    run = _validate(env, FakeSandbox())
    assert run.steps[2].status is StepStatus.NOT_FOUND
    assert run.steps[2].detail == "no tests found (no test script)"
    assert run.tests_discovered == 0


def test_not_an_npm_project(env):
    run = _validate(env, FakeSandbox())
    assert {s.status for s in run.steps} == {StepStatus.SKIPPED}
    assert "no package.json" in run.steps[0].detail

    _package(env, None, raw="{broken")
    run = _validate(env, FakeSandbox())
    assert run.steps[0].status is StepStatus.FAILED

    _package(env, None, raw='{"scripts": ["x"]}')
    assert _validate(env, FakeSandbox()).steps[0].status is StepStatus.FAILED


def test_script_plan_table():
    juice = node_script_plan(JUICE_SCRIPTS)
    assert (juice.profile, juice.build_script, juice.test_script) == (
        "juice-shop",
        "build:server",
        "test:server",
    )
    partial = node_script_plan({"build:server": "tsc"})
    assert partial.test_script is None
    assert partial.test_skip_reason == "no tests found (no test:server)"
    only_tests = node_script_plan({"test:server": "node --test"})
    assert only_tests.build_skip_reason == "no build:server script"
    assert node_script_plan({}).test_script is None
    for script in ("postinstall", "test:frontend", "test:api", "prepare"):
        with pytest.raises(ValueError, match="Refusing"):
            _npm_command(script)


def test_write_log_caps_size(tmp_path):
    path = Path(write_log(tmp_path / "logs", "test", "x" * 5000, 200))
    data = path.read_bytes()
    assert len(data) <= 200
    assert data.endswith(b"truncated at 200 bytes]\n")

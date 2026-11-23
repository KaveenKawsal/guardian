import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from guardian.core.config import GuardianSettings
from guardian.execution.results import ToolResult, ToolStatus
from guardian.execution.runner import ToolRunner
from guardian.sources import (
    CloneError,
    InvalidTargetError,
    LocalTarget,
    RemoteTarget,
    clone,
    parse_target,
    remove_workspace,
    workspaces_dir,
)
from guardian.sources.remote import workspace_path

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


# --- parsing --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "url", "display", "name", "ref"),
    [
        (
            "https://github.com/juice-shop/juice-shop",
            "https://github.com/juice-shop/juice-shop",
            "github.com/juice-shop/juice-shop",
            "juice-shop",
            None,
        ),
        ("https://github.com/o/r.git", "https://github.com/o/r", "github.com/o/r", "r", None),
        ("https://github.com/o/r.git/", "https://github.com/o/r", "github.com/o/r", "r", None),
        ("https://GitHub.com/o/r", "https://github.com/o/r", "github.com/o/r", "r", None),
        (
            "https://github.com/o/r/tree/v1.2",
            "https://github.com/o/r",
            "github.com/o/r",
            "r",
            "v1.2",
        ),
        (
            "https://github.com/o/r/tree/main/src/app",
            "https://github.com/o/r",
            "github.com/o/r",
            "r",
            "main",
        ),
        (
            "https://github.com/o/r/blob/dev/x.py",
            "https://github.com/o/r",
            "github.com/o/r",
            "r",
            "dev",
        ),
        ("https://github.com/o/r/pulls", "https://github.com/o/r", "github.com/o/r", "r", None),
        (
            "https://github.com/o/r?tab=readme#top",
            "https://github.com/o/r",
            "github.com/o/r",
            "r",
            None,
        ),
        ("github.com/o/r", "https://github.com/o/r", "github.com/o/r", "r", None),
        ("www.github.com/o/r", "https://www.github.com/o/r", "www.github.com/o/r", "r", None),
        ("github.com/o/r/tree/feat", "https://github.com/o/r", "github.com/o/r", "r", "feat"),
        (
            "octo-org/hello.world",
            "https://github.com/octo-org/hello.world",
            "github.com/octo-org/hello.world",
            "hello.world",
            None,
        ),
        ('  "https://github.com/o/r"  ', "https://github.com/o/r", "github.com/o/r", "r", None),
        ("'o/r'", "https://github.com/o/r", "github.com/o/r", "r", None),
        (
            "https://gitlab.com/group/sub/repo/-/tree/release",
            "https://gitlab.com/group/sub/repo",
            "gitlab.com/group/sub/repo",
            "repo",
            "release",
        ),
        (
            "https://gitlab.com/group/sub/repo.git",
            "https://gitlab.com/group/sub/repo",
            "gitlab.com/group/sub/repo",
            "repo",
            None,
        ),
        (
            "https://bitbucket.org/team/proj/src/develop/README.md",
            "https://bitbucket.org/team/proj",
            "bitbucket.org/team/proj",
            "proj",
            "develop",
        ),
        (
            "https://git.example.com:8443/scm/team/app.git",
            "https://git.example.com:8443/scm/team/app",
            "git.example.com:8443/scm/team/app",
            "app",
            None,
        ),
        (
            "https://git.example.com:443/a/b",
            "https://git.example.com/a/b",
            "git.example.com/a/b",
            "b",
            None,
        ),
        (
            "https://git.example.com/a/b/tree/x",
            "https://git.example.com/a/b",
            "git.example.com/a/b",
            "b",
            "x",
        ),
    ],
)
def test_parse_remote(text, url, display, name, ref):
    target = parse_target(text)
    assert isinstance(target, RemoteTarget)
    assert (target.url, target.display, target.name, target.ref) == (url, display, name, ref)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", "No scan target"),
        ('  ""  ', "No scan target"),
        ("http://github.com/o/r", "insecure"),
        ("HTTP://github.com/o/r", "insecure"),
        ("file:///etc/passwd", "file://"),
        ("ext::sh -c touch% /tmp/pwned", "transport syntax"),
        ("fd::17", "transport syntax"),
        ("ssh://git@github.com/o/r.git", "SSH"),
        ("git+ssh://github.com/o/r", "SSH"),
        ("git@github.com:o/r.git", "SSH"),
        ("git://github.com/o/r", "Unsupported URL scheme"),
        ("ftp://host/o/r", "Unsupported URL scheme"),
        ("https://token@github.com/o/r", "credentials"),
        ("https://user:pw@github.com/o/r", "credentials"),
        ("--upload-pack=evil", "must not start with '-'"),
        ("-o/r", "must not start with '-'"),
        ("https://github.com/o/r\nfoo", "control characters"),
        ("o/r\x00", "control characters"),
        ("https://github.com/o r/x", "whitespace"),
        ("some thing", "Not an existing directory"),
        ("https://github.com/onlyowner", "does not point to a repository"),
        ("https://github.com/", "does not point to a repository"),
        ("https:///o/r", "valid host"),
        ("https://bad_host!/o/r", "valid host"),
        ("https://github.com:99999/o/r", "invalid port"),
        ("https://github.com/o/r%20x", "Unsupported characters"),
        ("https://github.com/o/..", "Unsupported characters"),
        ("https://github.com/o/r/tree/-evil", "Invalid branch"),
        ("https://github.com/o/r/tree/a..b", "Invalid branch"),
        ("./missing-dir", "Local directory not found"),
        ("C:\\nope\\repo", "Local directory not found"),
        ("~/definitely-missing-guardian-dir", "Local directory not found"),
        ("a/b/c", "Not an existing directory or a supported repository"),
        ("justaword", "Not an existing directory or a supported repository"),
    ],
)
def test_parse_rejects(text, message):
    with pytest.raises(InvalidTargetError, match=message):
        parse_target(text)


def test_parse_local_wins_over_shorthand(tmp_path, monkeypatch):
    (tmp_path / "owner" / "repo").mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    target = parse_target("owner/repo")
    assert isinstance(target, LocalTarget)
    assert target.display == str(Path("owner/repo"))
    spaced = tmp_path / "my project"
    spaced.mkdir()
    assert parse_target(f'"{spaced}"') == LocalTarget(spaced)


def test_with_ref():
    target = parse_target("o/r")
    assert isinstance(target, RemoteTarget)
    assert target.with_ref(None) is target
    assert target.with_ref("release/1.x").ref == "release/1.x"
    with pytest.raises(InvalidTargetError):
        target.with_ref("--force")


# --- workspaces ---------------------------------------------------------------------------


@pytest.fixture
def settings(tmp_path) -> GuardianSettings:
    return GuardianSettings(data_dir=tmp_path / "data", change_history_commits=5)


def test_workspace_path_is_stable_and_named_after_repo(settings):
    a = parse_target("https://github.com/o/r.git")
    b = parse_target("github.com/o/r/tree/dev")
    assert isinstance(a, RemoteTarget)
    assert isinstance(b, RemoteTarget)
    assert workspace_path(a, settings) == workspace_path(b, settings)
    assert workspace_path(a, settings).name == "r"
    assert workspace_path(a, settings).parent.parent == workspaces_dir(settings)
    con = RemoteTarget(url="https://h.example/o/con", host="h.example", path="o/con")
    assert workspace_path(con, settings).name == "con_repo"


def test_remove_workspace_refuses_outside(settings, tmp_path):
    outside = tmp_path / "precious"
    outside.mkdir()
    with pytest.raises(CloneError, match="outside"):
        remove_workspace(outside, settings)
    with pytest.raises(CloneError, match="outside"):
        remove_workspace(workspaces_dir(settings), settings)
    with pytest.raises(CloneError, match="outside"):
        remove_workspace(workspaces_dir(settings) / ".." / "x", settings)
    assert outside.exists()
    remove_workspace(workspaces_dir(settings) / "never-created", settings)  # no-op


def test_remove_workspace_handles_read_only_files(settings):
    victim = workspaces_dir(settings) / "abc" / "repo"
    (victim / "objects").mkdir(parents=True)
    pack = victim / "objects" / "pack.idx"
    pack.write_text("x")
    pack.chmod(stat.S_IREAD)
    remove_workspace(victim, settings)
    assert not victim.exists()


# --- cloning through the real git binary ----------------------------------------------------


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=t", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
    )


@pytest.fixture
def upstream(tmp_path) -> Path:
    src = tmp_path / "upstream"
    src.mkdir()
    _git(src, "init", "-q", "-b", "main")
    (src / "app.js").write_text("console.log(1)\n")
    _git(src, "add", ".")
    _git(src, "commit", "-qm", "one")
    _git(src, "branch", "dev")
    (src / "two.js").write_text("2\n")
    _git(src, "add", ".")
    _git(src, "commit", "-qm", "two")
    return src


def _file_target(src: Path, ref: str | None = None) -> RemoteTarget:
    return RemoteTarget(url=src.as_uri(), host="local", path="o/upstream", ref=ref)


@needs_git
def test_clone_local_repo_over_file_transport(upstream, settings):
    dest = clone(_file_target(upstream), settings, ToolRunner(), allow_file_transport=True)
    assert dest.name == "upstream"
    assert (dest / "two.js").exists()
    # Re-cloning replaces the previous workspace at the same path.
    again = clone(_file_target(upstream, "dev"), settings, ToolRunner(), allow_file_transport=True)
    assert again == dest
    assert not (dest / "two.js").exists()
    assert (dest / "app.js").exists()
    remove_workspace(dest, settings)
    assert not dest.exists()


@needs_git
def test_clone_missing_ref(upstream, settings):
    target = _file_target(upstream, "nope")
    with pytest.raises(CloneError, match="'nope' not found"):
        clone(target, settings, ToolRunner(), allow_file_transport=True)
    assert not workspace_path(target, settings).exists()


@needs_git
def test_file_and_ext_transports_stay_blocked(upstream, settings, tmp_path):
    with pytest.raises(CloneError, match="blocked"):
        clone(_file_target(upstream), settings, ToolRunner())
    marker = tmp_path / "pwned"
    ext = RemoteTarget(url=f"ext::sh -c touch% {marker.as_posix()}", host="x", path="o/r")
    with pytest.raises(CloneError, match="blocked"):
        clone(ext, settings, ToolRunner())
    assert not marker.exists()


@needs_git
def test_https_override_reaches_the_network_layer(settings):
    # Port 1 on loopback refuses connections: reaching "connect" proves https is allowed.
    target = RemoteTarget(url="https://127.0.0.1:1/o/r", host="127.0.0.1:1", path="o/r")
    with pytest.raises(CloneError, match="Could not connect"):
        clone(target, settings, ToolRunner())


# --- failure mapping ------------------------------------------------------------------------


class FakeRunner:
    def __init__(self, result: ToolResult) -> None:
        self.result = result
        self.calls: list[list[str]] = []

    def run(self, tool, args, **kwargs):
        self.calls.append(list(args))
        return self.result


def _failed(stderr: str, status: ToolStatus = ToolStatus.FAILED) -> ToolResult:
    return ToolResult(tool="git", args=[], status=status, exit_code=128, stderr=stderr, error="e")


@pytest.mark.parametrize(
    ("result", "message"),
    [
        (
            _failed(
                "fatal: could not read Username for 'https://github.com': terminal prompts disabled"
            ),
            "not found or private",
        ),
        (
            _failed("remote: Repository not found.\nfatal: repository 'x' not found"),
            "not found or private",
        ),
        (
            _failed("fatal: unable to access: Could not resolve host: github.com"),
            "Could not resolve host",
        ),
        (_failed("fatal: Failed to connect to github.com port 443"), "Could not connect"),
        (_failed("SSL certificate problem: unable to get local issuer"), "TLS/certificate"),
        (_failed("fatal: something odd"), r"failed \(exit code 128\)"),
        (_failed("", ToolStatus.TIMEOUT), "timed out"),
        (_failed("", ToolStatus.NOT_FOUND), "git is not installed"),
        (_failed("", ToolStatus.ERROR), "Could not run git"),
    ],
)
def test_clone_failure_messages(result, message, settings):
    target = parse_target("https://github.com/o/r")
    assert isinstance(target, RemoteTarget)
    with pytest.raises(CloneError, match=message):
        clone(target, settings, FakeRunner(result))  # ty: ignore[invalid-argument-type]


def test_clone_arguments(settings):
    runner = FakeRunner(ToolResult(tool="git", args=[], status=ToolStatus.SUCCESS, exit_code=0))
    target = parse_target("https://github.com/o/r/tree/v2")
    assert isinstance(target, RemoteTarget)
    dest = clone(target, settings, runner)  # ty: ignore[invalid-argument-type]
    args = runner.calls[0]
    assert args[:2] == ["-c", "protocol.https.allow=always"]
    assert "core.symlinks=false" in args
    assert args[args.index("--depth") + 1] == "5"
    assert args[args.index("--branch") + 1] == "v2"
    assert args[-3:] == ["--", "https://github.com/o/r", str(dest)]
    assert {"--no-tags", "--single-branch", "--no-recurse-submodules"} <= set(args)

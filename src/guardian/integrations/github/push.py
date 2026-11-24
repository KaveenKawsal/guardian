"""Push Guardian's ``guardian/fix-*`` branch to GitHub over https, and nothing else.

Why it is safe (ADR 11, "Pull requests"):

* **No hostile config on the push.** The scanned repository's ``.git/config`` is untrusted: it
  could rewrite the URL (``url.*.insteadOf``), turn off TLS verification, add a proxy or a
  credential helper. So the push does not run in that repository. Guardian creates a fresh,
  empty bare repository of its own whose ``objects/info/alternates`` points at the scanned
  repository's object store (objects are data, config is not read), and pushes the verified
  commit from there. The user's global git config is ignored for this call too
  (``GIT_CONFIG_GLOBAL`` = the null device), so a personal ``insteadOf`` to ssh cannot
  redirect it; the system config (admin-controlled) still applies.
* **Only https, only for this command.** ``ToolRunner`` always adds ``protocol.allow=never``
  and ``credential.helper=`` (as ``-c`` and as ``GIT_CONFIG_*``). This call adds
  ``-c protocol.https.allow=always`` (the per-protocol key overrides ``protocol.allow``; every
  other transport stays disabled) and ``-c http.followRedirects=false``.
* **The token never appears in argv, a URL, a log or any config file.** The credential helper
  is a shell snippet that echoes ``$GUARDIAN_GIT_TOKEN``; the variable is set only in this git
  process's environment (``ToolRunner.run(env=...)``). The helper is scoped to
  ``https://github.com`` (``credential.https://github.com.helper``) after ``credential.helper=``
  has reset every helper configured earlier, so git hands the token to no other host. Command
  line ``-c`` values are read after ``GIT_CONFIG_*`` and after every config file, which is what
  makes the reset win (verified against git in the tests).
* **Branch guard.** The refspec is ``<verified sha>:refs/heads/guardian/fix-<case>``: no ``+``,
  no ``--force``, no other branch, never the base/default branch. A non-fast-forward is
  rejected by git and reported, not forced.
"""

import os
import re
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from pydantic import SecretStr

from guardian.execution.policies import GIT_PUSH_POLICY
from guardian.execution.runner import ToolRunner
from guardian.integrations.github.remote import GITHUB_ORIGIN, GitHubRepo, PrError
from guardian.remediation.apply import BRANCH_PREFIX

TOKEN_ENV = "GUARDIAN_GIT_TOKEN"  # noqa: S105 - a variable name, not a secret
GIT_USERNAME = "x-access-token"
_CASE_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
_SHA = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_PUSH_TIMEOUT = 300
_GIT_TIMEOUT = 60
MAX_ERROR_CHARS = 400

# `test "$1" = get`: answer only "get" (not "store"/"erase"). The value comes from the
# environment at run time; the literal text below contains no secret.
CREDENTIAL_HELPER = (
    f'!f() {{ test "$1" = get || exit 0; echo username={GIT_USERNAME}; '
    f'echo "password=${TOKEN_ENV}"; }}; f'
)

PUSH_CONFIG_ARGS: tuple[str, ...] = (
    "-c",
    "protocol.https.allow=always",
    "-c",
    "http.followRedirects=false",
    "-c",
    "credential.helper=",
    "-c",
    f"credential.{GITHUB_ORIGIN}.helper={CREDENTIAL_HELPER}",
)


@dataclass(frozen=True)
class PushResult:
    repo: GitHubRepo
    branch: str
    commit_sha: str
    output: str


def assert_pushable_branch(branch: str, case_id: str, *, base: str | None = None) -> None:
    """Only ``guardian/fix-<case_id>``; never the base branch."""
    if not _CASE_ID.fullmatch(case_id):
        msg = f"Refusing unsafe case id {case_id[:70]!r}"
        raise PrError(msg)
    if branch != f"{BRANCH_PREFIX}{case_id}":
        msg = f"Refusing to push {branch[:80]!r}: only {BRANCH_PREFIX}{case_id} may be pushed"
        raise PrError(msg)
    if base is not None and branch == base:
        msg = f"Refusing to push the base branch {base!r}"
        raise PrError(msg)


def scrub(text: str, token: SecretStr | None) -> str:
    """One line, bounded, with the token (if any) replaced."""
    line = " ".join(text.split())
    if token is not None and (secret := token.get_secret_value()):
        line = line.replace(secret, "***")
    return line[:MAX_ERROR_CHARS]


def push_env(token: SecretStr) -> dict[str, str]:
    """The only extra environment of the push: the token and no user-level git config."""
    return {TOKEN_ENV: token.get_secret_value(), "GIT_CONFIG_GLOBAL": os.devnull}


def push_argv(git_dir: Path, repo: GitHubRepo, commit_sha: str, branch: str) -> list[str]:
    """Arguments after ``git`` (``ToolRunner`` prepends the hardening ``-c`` first)."""
    if not _SHA.fullmatch(commit_sha):
        msg = f"Refusing to push {commit_sha[:70]!r}: not a full commit sha"
        raise PrError(msg)
    return [
        *PUSH_CONFIG_ARGS,
        f"--git-dir={git_dir}",
        "push",
        "--porcelain",
        "--no-verify",
        repo.push_url,
        f"{commit_sha}:refs/heads/{branch}",
    ]


def _check(runner: ToolRunner, cwd: Path, args: list[str], what: str) -> str:
    result = runner.run("git", args, cwd=cwd, timeout_seconds=_GIT_TIMEOUT)
    if not result.ok:
        detail = scrub(result.stderr or result.error or "", None)
        msg = f"{what} failed: {detail}"
        raise PrError(msg)
    return result.stdout.strip()


def _object_store(runner: ToolRunner, worktree: Path) -> Path:
    common = _check(
        runner,
        worktree,
        ["rev-parse", "--path-format=absolute", "--git-common-dir"],
        "Locating the repository",
    )
    objects = Path(common) / "objects"
    if not objects.is_dir():
        msg = f"No git object store at {objects}"
        raise PrError(msg)
    return objects.resolve()


def _verified_head(runner: ToolRunner, worktree: Path, commit_sha: str) -> str:
    head = _check(
        runner, worktree, ["rev-parse", "--verify", "HEAD^{commit}"], "Reading the fix commit"
    )
    if head.lower() != commit_sha.lower():
        msg = (
            f"The worktree is at {head[:12]}, not the verified commit {commit_sha[:12]}; "
            "refusing to push an unverified change"
        )
        raise PrError(msg)
    return head.lower()


def push_branch(  # noqa: PLR0913 - every input is explicit; nothing is read from the repo config
    runner: ToolRunner | None,
    *,
    worktree: Path,
    repo: GitHubRepo,
    case_id: str,
    branch: str,
    commit_sha: str,
    token: SecretStr,
    base: str | None = None,
    tmp_factory: Callable[[], str] = lambda: tempfile.mkdtemp(prefix="guardian-push-"),
) -> PushResult:
    """Push the verified commit of ``worktree`` to ``repo`` as ``branch``. Raises ``PrError``."""
    assert_pushable_branch(branch, case_id, base=base)
    git = runner or ToolRunner(GIT_PUSH_POLICY)
    sha = _verified_head(git, worktree, commit_sha)
    objects = _object_store(git, worktree)
    staging = Path(tmp_factory())
    try:
        git_dir = staging / "push.git"
        _check(git, staging, ["init", "--quiet", "--bare", str(git_dir)], "Preparing the push")
        alternates = git_dir / "objects" / "info" / "alternates"
        alternates.parent.mkdir(parents=True, exist_ok=True)
        alternates.write_text(f"{objects}\n", encoding="utf-8")
        result = git.run(
            "git",
            push_argv(git_dir, repo, sha, branch),
            cwd=staging,
            timeout_seconds=_PUSH_TIMEOUT,
            env=push_env(token),
        )
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    output = scrub(f"{result.stdout} {result.stderr}", token)
    if not result.ok:
        reason = scrub(result.error or "", token) or output or "git push failed"
        msg = f"git push to {repo.full_name} failed: {reason}"
        raise PrError(msg)
    return PushResult(repo=repo, branch=branch, commit_sha=sha, output=output)

"""GitHub pull requests: remote validation, the isolated https push, the REST client, the body."""

import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from jira_fake import seed_case, seed_scan
from pydantic import SecretStr
from remediation_fakes import FakeRunner, git, init_repo, ok

from guardian.core.config import GuardianSettings
from guardian.core.remediation_models import (
    Confidence,
    DecisionType,
    HumanDecision,
    SbomDiff,
    StepStatus,
    ValidationRun,
    ValidationStep,
    VerificationResult,
    VerificationStatus,
)
from guardian.execution.policies import (
    GIT_HARDENING_ARGS,
    GIT_HARDENING_ENV,
    GIT_PUSH_POLICY,
    ExecutionPolicy,
)
from guardian.execution.runner import ToolRunner
from guardian.integrations.github import body as body_module
from guardian.integrations.github.client import GitHubClient, GitHubError, is_already_exists
from guardian.integrations.github.pr import open_pull_request
from guardian.integrations.github.push import (
    CREDENTIAL_HELPER,
    PUSH_CONFIG_ARGS,
    TOKEN_ENV,
    assert_pushable_branch,
    push_argv,
    push_branch,
    push_env,
)
from guardian.integrations.github.records import pr_url_is_safe, pull_request_of
from guardian.integrations.github.remote import (
    GitHubRepo,
    PrError,
    parse_github_remote,
    resolve_github_repo,
)
from guardian.storage.database import Database

TOKEN = "ghp_TESTTOKEN_0123456789abcdef"  # noqa: S105
CASE = "rc_0123456789ab"
BRANCH = f"guardian/fix-{CASE}"
SHA = "a" * 40
REPO = GitHubRepo("acme", "juice-shop")


# --- remote URL validation ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "owner", "name"),
    [
        ("https://github.com/acme/juice-shop.git", "acme", "juice-shop"),
        ("https://github.com/acme/juice-shop", "acme", "juice-shop"),
        ("https://github.com/acme/juice-shop/", "acme", "juice-shop"),
        ("https://GitHub.com/Acme-1/repo.name_x.git", "Acme-1", "repo.name_x"),
        ("  https://github.com/acme/r.git\n", "acme", "r"),
    ],
)
def test_github_remote_accepted(url, owner, name):
    repo = parse_github_remote(url)
    assert (repo.owner, repo.name) == (owner, name)
    assert repo.push_url == f"https://github.com/{owner}/{name}.git"


@pytest.mark.parametrize(
    "url",
    [
        "git@github.com:acme/juice-shop.git",
        "ssh://git@github.com/acme/juice-shop.git",
        "http://github.com/acme/juice-shop.git",
        "https://gitlab.com/acme/juice-shop.git",
        "https://github.com.evil.example/acme/juice-shop.git",
        "https://evil.example/github.com/acme/juice-shop.git",
        "https://user:pass@github.com/acme/juice-shop.git",
        f"https://x-access-token:{TOKEN}@github.com/acme/juice-shop.git",
        "https://github.com:443/acme/juice-shop.git",
        "https://github.com/acme/juice-shop.git?x=1",
        "https://github.com/acme/juice-shop.git#frag",
        "https://github.com/acme/../juice-shop.git",
        "https://github.com/acme/..",
        "https://github.com/acme",
        "https://github.com/-acme/repo",
        "https://github.com/acme/juice shop",
        "https://github.com/acme/juice-shop.git.git",
        "file:///tmp/repo.git",
        "",
    ],
)
def test_other_remotes_refused(url):
    with pytest.raises(PrError) as info:
        parse_github_remote(url)
    assert TOKEN not in str(info.value)
    assert "pass@" not in str(info.value)


def test_resolve_reads_the_remote_through_the_runner(tmp_path):
    runner = FakeRunner(lambda tool, args, cwd: ok(tool, args, "https://github.com/acme/app\n"))
    assert resolve_github_repo(runner, tmp_path, "origin") == GitHubRepo("acme", "app")
    assert runner.calls[0][:2] == ("git", ["remote", "get-url", "origin"])

    missing = FakeRunner(lambda tool, args, cwd: ok(tool, args, exit_code=2))
    with pytest.raises(PrError, match="no git remote"):
        resolve_github_repo(missing, tmp_path, "origin")
    two = FakeRunner(lambda tool, args, cwd: ok(tool, args, "https://github.com/a/b\nx\n"))
    with pytest.raises(PrError, match="single URL"):
        resolve_github_repo(two, tmp_path, "origin")
    with pytest.raises(PrError, match="unsafe"):
        resolve_github_repo(runner, tmp_path, "--upload-pack=x")


def test_pr_remote_setting_is_validated(tmp_path):
    with pytest.raises(ValueError, match="GUARDIAN_PR_REMOTE"):
        GuardianSettings(_env_file=None, data_dir=tmp_path, pr_remote="-x")


# --- push ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("branch", "base"),
    [
        ("main", None),
        ("guardian/fix-rc_other", None),
        (f"{BRANCH}-x", None),
        ("guardian/fix-", None),
        (BRANCH, BRANCH),
    ],
)
def test_branch_guard(branch, base):
    with pytest.raises(PrError):
        assert_pushable_branch(branch, CASE, base=base)


def test_branch_guard_refuses_unsafe_case_id():
    with pytest.raises(PrError, match="unsafe case id"):
        assert_pushable_branch("guardian/fix-../x", "../x")
    assert_pushable_branch(BRANCH, CASE, base="main")


def _push_handler(head=SHA, common=None, push_exit=0, push_stderr=""):
    def handle(tool, args, cwd):
        if "rev-parse" in args and "--git-common-dir" in args:
            return ok(tool, args, str(common) + "\n")
        if "rev-parse" in args:
            return ok(tool, args, head + "\n")
        if "push" in args:
            result = ok(tool, args, exit_code=push_exit)
            return result.model_copy(update={"stderr": push_stderr})
        return ok(tool, args)

    return handle


def test_push_argv_and_env_exact(tmp_path):
    common = tmp_path / "repo" / ".git"
    (common / "objects").mkdir(parents=True)
    staging = tmp_path / "staging"
    runner = FakeRunner(_push_handler(common=common))
    result = push_branch(
        runner,
        worktree=tmp_path / "wt",
        repo=REPO,
        case_id=CASE,
        branch=BRANCH,
        commit_sha=SHA,
        token=SecretStr(TOKEN),
        base="main",
        tmp_factory=lambda: str(staging.mkdir() or staging),
    )
    assert result.commit_sha == SHA
    push_call = next(c for c in runner.calls if "push" in c[1])
    git_dir = staging / "push.git"
    assert push_call[1] == [
        "-c",
        "protocol.https.allow=always",
        "-c",
        "http.followRedirects=false",
        "-c",
        "credential.helper=",
        "-c",
        f"credential.https://github.com.helper={CREDENTIAL_HELPER}",
        f"--git-dir={git_dir}",
        "push",
        "--porcelain",
        "--no-verify",
        "https://github.com/acme/juice-shop.git",
        f"{SHA}:refs/heads/{BRANCH}",
    ]
    assert push_call[2] == staging  # never the scanned repository
    for tool, args, _, _ in runner.calls:
        assert tool == "git"
        assert not any(TOKEN in a for a in args)
        assert "--force" not in args
        assert not any(a.startswith("+") for a in args)
    env = runner.envs[runner.calls.index(push_call)]
    assert env == {TOKEN_ENV: TOKEN, "GIT_CONFIG_GLOBAL": os.devnull}
    assert all(e is None for i, e in enumerate(runner.envs) if runner.calls[i] is not push_call)
    assert not staging.exists()  # cleaned up
    alternates_written = [c for c in runner.calls if c[1][:2] == ["init", "--quiet"]]
    assert alternates_written


def test_push_refuses_a_worktree_not_at_the_verified_commit(tmp_path):
    runner = FakeRunner(_push_handler(head="b" * 40, common=tmp_path))
    with pytest.raises(PrError, match="unverified"):
        push_branch(
            runner,
            worktree=tmp_path,
            repo=REPO,
            case_id=CASE,
            branch=BRANCH,
            commit_sha=SHA,
            token=SecretStr(TOKEN),
        )
    assert not any("push" in c[1] for c in runner.calls)


def test_push_failure_is_scrubbed(tmp_path):
    common = tmp_path / ".git"
    (common / "objects").mkdir(parents=True)
    runner = FakeRunner(
        _push_handler(common=common, push_exit=1, push_stderr=f"! [rejected] auth {TOKEN} bad")
    )
    with pytest.raises(PrError) as info:
        push_branch(
            runner,
            worktree=tmp_path,
            repo=REPO,
            case_id=CASE,
            branch=BRANCH,
            commit_sha=SHA,
            token=SecretStr(TOKEN),
        )
    assert TOKEN not in str(info.value)
    assert "rejected" in str(info.value)


def test_push_argv_rejects_non_sha():
    with pytest.raises(PrError, match="full commit sha"):
        push_argv(Path("/x"), REPO, "HEAD", BRANCH)


def test_push_policy_is_git_only():
    assert GIT_PUSH_POLICY.allowed_tools == frozenset({"git"})
    assert "protocol.allow=never" in GIT_HARDENING_ARGS
    assert not any("protocol.https" in a for a in GIT_HARDENING_ARGS)


def test_token_env_never_inherited():
    source = {
        "PATH": "/bin",
        "GH_TOKEN": "x",
        "GITHUB_TOKEN": "y",
        "GUARDIAN_GITHUB_TOKEN": "z",
        "GUARDIAN_GIT_TOKEN": "w",
    }
    assert ExecutionPolicy().build_env(source) == {"PATH": "/bin"}
    widened = ExecutionPolicy(env_allowlist=frozenset({"PATH", "GH_TOKEN", "GITHUB_TOKEN"}))
    assert widened.build_env(source) == {"PATH": "/bin"}


def _git_env(**extra):
    env = {"PATH": os.environ["PATH"], "HOME": os.environ.get("HOME", "/tmp")}
    env.update(GIT_HARDENING_ENV)
    env.update(extra)
    return env


def test_real_git_credential_precedence_beats_hostile_config(tmp_path):
    """With Guardian's hardening (-c and GIT_CONFIG_*) plus the push overrides, git answers
    with the token only for https://github.com, even when a repository config tries to plant
    its own helpers."""
    hostile = tmp_path / "hostile"
    init_repo(hostile, {"a.txt": "a"})
    git(hostile, "config", "credential.helper", "!echo password=EVIL #")
    git(hostile, "config", "credential.https://github.com.helper", "!echo password=EVIL2 #")
    argv = ["git", *GIT_HARDENING_ARGS, *PUSH_CONFIG_ARGS, "credential", "fill"]
    env = _git_env(**push_env(SecretStr(TOKEN)))

    def fill(host):
        return subprocess.run(
            argv,
            cwd=hostile,
            env=env,
            input=f"protocol=https\nhost={host}\n\n",
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )

    github = fill("github.com")
    assert github.returncode == 0, github.stderr
    assert f"password={TOKEN}" in github.stdout
    assert "username=x-access-token" in github.stdout
    assert "EVIL" not in github.stdout
    other = fill("evil.example")
    assert TOKEN not in other.stdout
    assert other.returncode != 0  # no helper answers, prompts are disabled

    # https is enabled by the push args only; other transports stay disabled.
    allowed = subprocess.run(
        ["git", *GIT_HARDENING_ARGS, *PUSH_CONFIG_ARGS, "config", "--get", "protocol.allow"],
        cwd=hostile,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert allowed.stdout.strip() == "never"


class RewritingRunner(ToolRunner):
    """Real git, but the GitHub URL is rewritten to a local bare repository (file://) and that
    transport is allowed for the test only."""

    def __init__(self, target: Path):
        super().__init__(GIT_PUSH_POLICY)
        self.target = target
        self.argv: list[list[str]] = []

    def run(self, tool, args, *, cwd, timeout_seconds=None, env=None):
        args = [f"file://{self.target}" if a == REPO.push_url else a for a in args]
        if "push" in args:
            args = ["-c", "protocol.file.allow=always", *args]
        self.argv.append(list(args))
        return super().run(tool, args, cwd=cwd, timeout_seconds=timeout_seconds, env=env)


def test_real_isolated_push_ignores_hostile_repo_config(tmp_path):
    root = tmp_path / "repo"
    init_repo(root, {"package.json": "{}\n"})
    remote = tmp_path / "remote.git"
    decoy = tmp_path / "decoy.git"
    git(tmp_path, "init", "-q", "--bare", str(remote))
    git(tmp_path, "init", "-q", "--bare", str(decoy))
    # A hostile repository config would redirect the push if it were read.
    git(root, "config", f"url.file://{decoy}.insteadOf", f"file://{remote}")
    worktree = tmp_path / "wt"
    git(root, "worktree", "add", "-q", "-b", BRANCH, str(worktree))
    (worktree / "package.json").write_text('{"x": 1}\n', encoding="utf-8")
    git(worktree, "commit", "-q", "-am", "fix")
    sha = git(worktree, "rev-parse", "HEAD")

    runner = RewritingRunner(remote)
    result = push_branch(
        runner,
        worktree=worktree,
        repo=REPO,
        case_id=CASE,
        branch=BRANCH,
        commit_sha=sha,
        token=SecretStr(TOKEN),
        base="main",
    )
    assert result.commit_sha == sha
    assert git(remote, "rev-parse", f"refs/heads/{BRANCH}") == sha
    assert git(remote, "for-each-ref").count("refs/heads/") == 1  # only the fix branch
    assert not git(decoy, "for-each-ref")
    # Pushing again is a no-op (idempotent).
    push_branch(
        runner,
        worktree=worktree,
        repo=REPO,
        case_id=CASE,
        branch=BRANCH,
        commit_sha=sha,
        token=SecretStr(TOKEN),
    )
    assert all(TOKEN not in a for argv in runner.argv for a in argv)


# --- GitHub REST client -------------------------------------------------------------------


class FakeGitHub:
    """httpx.MockTransport GitHub: a repository, its pull requests, scripted failures."""

    def __init__(self, default_branch="main"):
        self.default_branch = default_branch
        self.pulls: list[dict] = []
        self.requests: list[httpx.Request] = []
        self.queued: list[httpx.Response] = []
        self.create_status: int | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        assert request.headers["authorization"] == f"Bearer {TOKEN}"
        if self.queued:
            return self.queued.pop(0)
        path = request.url.path
        if path == "/user":
            return httpx.Response(200, json={"login": "guardian-bot"})
        if path == "/repos/acme/juice-shop" and request.method == "GET":
            return httpx.Response(
                200,
                json={"default_branch": self.default_branch, "permissions": {"push": True}},
            )
        if path == "/repos/acme/juice-shop/pulls" and request.method == "GET":
            head = request.url.params["head"]
            found = [p for p in self.pulls if f"acme:{p['head']['ref']}" == head]
            return httpx.Response(200, json=found)
        if path == "/repos/acme/juice-shop/pulls" and request.method == "POST":
            if self.create_status:
                return httpx.Response(
                    self.create_status,
                    json={
                        "message": "Validation Failed",
                        "errors": [{"message": "A pull request already exists for acme:x."}],
                    },
                )
            data = json.loads(request.content)
            number = len(self.pulls) + 1
            pull = {
                "number": number,
                "html_url": f"https://github.com/acme/juice-shop/pull/{number}",
                "head": {"ref": data["head"]},
                "base": {"ref": data["base"]},
                "draft": data["draft"],
                "title": data["title"],
                "body": data["body"],
            }
            self.pulls.append(pull)
            return httpx.Response(201, json=pull)
        return httpx.Response(404, json={"message": "Not Found"})

    def client(self, sleeps=None) -> GitHubClient:
        return GitHubClient(
            SecretStr(TOKEN),
            self.http(),
            sleep=(sleeps.append if sleeps is not None else lambda _: None),
        )

    def http(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))

    def count(self, method, path):
        return sum(1 for r in self.requests if r.method == method and r.url.path == path)


def test_client_default_branch_find_and_create():
    fake = FakeGitHub(default_branch="develop")
    with fake.client() as github:
        assert github.default_branch(REPO) == "develop"
        assert github.find_open_pull(REPO, BRANCH) is None
        pull = github.create_pull(
            REPO, title="t", head=BRANCH, base="develop", body="b", draft=True
        )
        assert pull["number"] == 1
        assert github.find_open_pull(REPO, BRANCH)["number"] == 1
        assert github.user()["login"] == "guardian-bot"
    create = next(r for r in fake.requests if r.method == "POST")
    assert json.loads(create.content) == {
        "title": "t",
        "head": BRANCH,
        "base": "develop",
        "body": "b",
        "draft": True,
    }
    assert repr(fake.client()) == "GitHubClient(api.github.com)"


def test_client_retries_gets_but_never_creates():
    fake = FakeGitHub()
    sleeps: list[float] = []
    fake.queued = [
        httpx.Response(502),
        httpx.Response(403, headers={"x-ratelimit-remaining": "0", "Retry-After": "2"}),
        httpx.Response(429),
    ]
    with fake.client(sleeps) as github:
        assert github.default_branch(REPO) == "main"
    assert sleeps == [1.0, 2.0, 4.0]

    fake.queued = [httpx.Response(503)]
    with fake.client() as github, pytest.raises(GitHubError, match="HTTP 503"):
        github.create_pull(REPO, title="t", head=BRANCH, base="main", body="b", draft=True)
    assert fake.count("POST", "/repos/acme/juice-shop/pulls") == 1

    fake.queued = [httpx.Response(403, json={"message": "Resource not accessible"})]
    with fake.client() as github, pytest.raises(GitHubError, match="permission"):
        github.default_branch(REPO)


def test_client_errors_are_scrubbed_and_bounded():
    fake = FakeGitHub()
    fake.queued = [httpx.Response(401, json={"message": f"Bad credentials {TOKEN}"})]
    with fake.client() as github, pytest.raises(GitHubError) as info:
        github.user()
    assert TOKEN not in str(info.value)
    assert "check GH_TOKEN" in str(info.value)
    assert info.value.status_code == 401

    fake.queued = [httpx.Response(200, content=b"not json")]
    with fake.client() as github, pytest.raises(GitHubError, match="not JSON"):
        github.user()
    fake.queued = [httpx.Response(200, json={"no": "branch"})]
    with fake.client() as github, pytest.raises(GitHubError, match="default_branch"):
        github.default_branch(REPO)
    fake.queued = [httpx.Response(200, json={"not": "a list"})]
    with fake.client() as github, pytest.raises(GitHubError, match="unexpected"):
        github.find_open_pull(REPO, BRANCH)
    with fake.client() as github, pytest.raises(GitHubError, match="Invalid branch"):
        github.find_open_pull(REPO, "-x")
    fake.queued = [httpx.Response(302, headers={"Location": "https://evil.example/"})]
    with fake.client() as github:
        assert github.user() == {}  # not followed


def test_client_transport_errors():
    def boom(request):
        raise httpx.ConnectError("down", request=request)

    github = GitHubClient(
        SecretStr(TOKEN),
        httpx.Client(transport=httpx.MockTransport(boom)),
        sleep=lambda _: None,
        max_retries=1,
    )
    with pytest.raises(GitHubError, match="connection failed"):
        github.user()

    def slow(request):
        raise httpx.ReadTimeout("slow", request=request)

    github = GitHubClient(
        SecretStr(TOKEN), httpx.Client(transport=httpx.MockTransport(slow)), max_retries=0
    )
    with pytest.raises(GitHubError, match="timed out"):
        github.user()

    big = GitHubClient(
        SecretStr(TOKEN),
        httpx.Client(
            transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"x" * 50))
        ),
        max_response_bytes=10,
    )
    with pytest.raises(GitHubError, match="too large"):
        big.user()
    own = GitHubClient(SecretStr(TOKEN))
    own.close()


def test_already_exists_detection():
    assert is_already_exists(
        GitHubError("HTTP 422 - A pull request already exists", status_code=422)
    )
    assert not is_already_exists(GitHubError("HTTP 422 - other", status_code=422))


# --- body ---------------------------------------------------------------------------------


def test_inline_and_fenced_neutralise_markdown():
    assert body_module.inline("a`b") == "``a`b``"
    assert body_module.inline("`x") == "`` `x ``"
    assert body_module.inline("@admin <img src=x>\n[l](javascript:x)") == (
        "`@admin <img src=x> [l](javascript:x)`"
    )
    assert body_module.inline("") == "`-`"
    block = body_module.fenced("```\n@team\x07")
    assert block.startswith("````text\n")
    assert block.endswith("\n````")
    assert "\x07" not in block


def _verification(case_id, **extra):
    values = {"reasons": ["targets resolved", "<script>@everyone"]} | extra
    return VerificationResult(
        case_id=case_id,
        before_scan_id="scan-1",
        after_scan_id="after-1",
        target_findings_resolved=["vuln-jsonwebtoken-0.4.0"],
        sbom_diff=SbomDiff(
            changed=[
                {
                    "purl_base": "pkg:npm/jsonwebtoken",
                    "from_version": "0.4.0",
                    "to_version": "4.2.2",
                }
            ]
        ),
        risk_before=72.5,
        risk_after=10.0,
        status=VerificationStatus.VERIFIED,
        confidence=Confidence.HIGH,
        **values,
    )


def _seed_pr_case(db, *, inferred=False):
    seed_scan(db)
    case, finding, _, candidates, _ = seed_case(db, inferred=inferred)
    db.findings.save("scan-1", [finding], [])
    decision = HumanDecision(
        case_id=case.id,
        decision=DecisionType.ACCEPT,
        actor_id="acc-1",
        actor_display="Alice `@admin`",
        channel="jira",
        jira_comment_id="10001",
        decided_at=datetime(2026, 1, 2, tzinfo=UTC),
    )
    db.remediation.save_decision(decision)
    db.remediation.save_decision(
        decision.model_copy(
            update={
                "decision": DecisionType.REVALIDATE,
                "jira_comment_id": "10002",
                "decided_at": datetime(2026, 1, 3, tzinfo=UTC),
            }
        )
    )
    db.remediation.link_jira(case.id, "SEC-7")
    db.remediation.save_validation(
        ValidationRun(
            case_id=case.id,
            branch=f"guardian/fix-{case.id}",
            worktree_path="/wt",
            commit_sha=SHA,
            sandbox="docker",
            steps=[
                ValidationStep(name="install", status=StepStatus.PASSED, exit_code=0),
                ValidationStep(name="build", status=StepStatus.PASSED, exit_code=0),
                ValidationStep(
                    name="test",
                    status=StepStatus.PASSED,
                    exit_code=0,
                    known_conflict=True,
                    detail="2 challenge tests",
                ),
            ],
            tests_discovered=3,
            tests_passed=3,
            tests_failed=0,
            started_at=datetime(2026, 1, 3, tzinfo=UTC),
        )
    )
    applied = {
        "case_id": case.id,
        "branch": f"guardian/fix-{case.id}",
        "worktree_path": "/wt",
        "commit_sha": SHA,
        "base_commit": "b" * 40,
        "changed_paths": ["package.json"],
        "candidate_id": candidates[0].id,
    }
    return case, applied


def test_pr_body_has_every_section_and_escapes(tmp_path):
    with Database(tmp_path / "g.db") as db:
        case, applied = _seed_pr_case(db, inferred=True)
        ctx = body_module.load_pr_context(
            db, case.id, applied, _verification(case.id).model_dump(mode="json")
        )
    title = body_module.pr_title(ctx)
    assert title == f"guardian: upgrade jsonwebtoken to 4.2.2 ({case.id})"
    body = body_module.pr_body(ctx)
    for expected in (
        f"`{case.id}`",
        "`GHSA-c7hr-j4mj-j2w6 (CVE-2015-9235)`",
        "**ACCEPT** by `` Alice `@admin` ``",
        "Jira: `SEC-7`",
        "Re-validated by",
        "Rollback: `git revert <commit>`",
        "| test | `passed` | 0 |",
        "known conflict: intentional challenge code; 2 challenge tests",
        "Verdict: **VERIFIED** (confidence `high`)",
        "Risk score: 72.5 → 10.0",
        "`pkg:npm/jsonwebtoken` `0.4.0` → `4.2.2`",
        "```text\ntargets resolved\n<script>@everyone\n```",
        "### AI assessment (inference, not verified)",
        "`groq / gpt-oss`",
        "Guardian never merges",
    ):
        assert expected in body, expected
    assert "@everyone" not in body.replace("```text\ntargets resolved\n<script>@everyone", "")


def test_pr_body_without_ai_or_validation(tmp_path):
    with Database(tmp_path / "g.db") as db:
        seed_scan(db)
        case = seed_case(db)[0]
        ctx = body_module.load_pr_context(
            db,
            case.id,
            {"branch": "b", "commit_sha": SHA},
            _verification(case.id).model_dump(mode="json"),
        )
    body = body_module.pr_body(ctx)
    assert "AI assessment" not in body
    assert "No validation run recorded." in body
    assert "No ACCEPT/MODIFY decision found" in body
    assert "finding `vuln-jsonwebtoken-0.4.0`" in body  # finding not stored: id shown
    long_ctx = body_module.PrContext(
        case=ctx.case,
        branch="b",
        commit_sha=SHA,
        candidate=None,
        decision=None,
        revalidated_by=None,
        jira_key=None,
        validation=None,
        verification=_verification(case.id, reasons=["x" * 3000] * 30),
    )
    big = body_module.pr_body(long_ctx)
    assert len(big) <= body_module.MAX_BODY_CHARS
    assert "human-provided branch/commit" in big
    assert body_module.pr_title(long_ctx).startswith("guardian: jsonwebtoken")


# --- open_pull_request --------------------------------------------------------------------


class FakePush:
    def __init__(self, error=None):
        self.calls: list[dict] = []
        self.error = error

    def __call__(self, runner, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error


def _origin_runner():
    return FakeRunner(
        lambda tool, args, cwd: ok(tool, args, "https://github.com/acme/juice-shop.git\n")
    )


def _pr_settings(tmp_path, **extra):
    values = {"data_dir": tmp_path, "pr_enabled": True, "github_token": TOKEN} | extra
    return GuardianSettings(_env_file=None, **values)


def test_open_pull_request_creates_then_reuses(tmp_path):
    fake = FakeGitHub()
    push = FakePush()
    with Database(tmp_path / "g.db") as db:
        case, applied = _seed_pr_case(db)
        verification = _verification(case.id).model_dump(mode="json")
        settings = _pr_settings(tmp_path)
        first = open_pull_request(
            db,
            settings,
            case.id,
            applied,
            verification,
            runner=_origin_runner(),
            http_client=fake.http(),
            push=push,
        )
        second = open_pull_request(
            db,
            settings,
            case.id,
            applied,
            verification,
            runner=_origin_runner(),
            http_client=fake.http(),
            push=push,
        )
    assert first["url"] == "https://github.com/acme/juice-shop/pull/1"
    assert first["reused"] is False
    assert first["draft"] is True
    assert first["base"] == "main"
    assert second["number"] == 1
    assert second["reused"] is True
    assert len(fake.pulls) == 1
    assert fake.count("POST", "/repos/acme/juice-shop/pulls") == 1
    assert push.calls[0]["branch"] == f"guardian/fix-{case.id}"
    assert push.calls[0]["base"] == "main"
    assert push.calls[0]["commit_sha"] == SHA
    assert "Guardian never merges" in fake.pulls[0]["body"]


def test_open_pull_request_handles_422_already_exists(tmp_path):
    fake = FakeGitHub()
    fake.create_status = 422
    with Database(tmp_path / "g.db") as db:
        case, applied = _seed_pr_case(db)
        verification = _verification(case.id).model_dump(mode="json")
        settings = _pr_settings(tmp_path, pr_base="release", pr_draft=False)
        # GitHub says it exists but the lookup finds nothing: the 422 is reported.
        with pytest.raises(GitHubError, match="already exists"):
            open_pull_request(
                db,
                settings,
                case.id,
                applied,
                verification,
                runner=_origin_runner(),
                http_client=fake.http(),
                push=FakePush(),
            )
        # ... and when the lookup finds it (a race), it is reused.
        fake.queued = [
            httpx.Response(200, json=[]),
            httpx.Response(422, json={"errors": [{"message": "A pull request already exists"}]}),
            httpx.Response(
                200,
                json=[
                    {
                        "number": 9,
                        "html_url": "https://github.com/acme/juice-shop/pull/9",
                        "head": {"ref": applied["branch"]},
                        "draft": False,
                    }
                ],
            ),
        ]
        result = open_pull_request(
            db,
            settings,
            case.id,
            applied,
            verification,
            runner=_origin_runner(),
            http_client=fake.http(),
            push=FakePush(),
        )
    assert result["number"] == 9
    assert result["reused"] is True
    assert result["base"] == "release"
    assert fake.count("GET", "/repos/acme/juice-shop") == 0  # pr_base set: no lookup


def test_open_pull_request_refusals(tmp_path):
    fake = FakeGitHub()
    with Database(tmp_path / "g.db") as db:
        case, applied = _seed_pr_case(db)
        verification = _verification(case.id).model_dump(mode="json")
        no_token = GuardianSettings(_env_file=None, data_dir=tmp_path, pr_enabled=True)
        with pytest.raises(PrError, match="no GitHub token"):
            open_pull_request(db, no_token, case.id, applied, verification, runner=_origin_runner())
        settings = _pr_settings(tmp_path)
        with pytest.raises(PrError, match="No applied change"):
            open_pull_request(
                db, settings, case.id, {"error": "x"}, verification, runner=_origin_runner()
            )
        with pytest.raises(PrError, match="only guardian/fix"):
            open_pull_request(
                db,
                settings,
                case.id,
                applied | {"branch": "main"},
                verification,
                runner=_origin_runner(),
            )
        ssh = FakeRunner(lambda tool, args, cwd: ok(tool, args, "git@github.com:acme/x.git\n"))
        with pytest.raises(PrError, match="not https://github.com"):
            open_pull_request(db, settings, case.id, applied, verification, runner=ssh)
        same_base = GuardianSettings(
            _env_file=None,
            data_dir=tmp_path,
            pr_enabled=True,
            github_token=TOKEN,
            pr_base=applied["branch"],
        )
        with pytest.raises(PrError, match="base branch"):
            open_pull_request(
                db,
                same_base,
                case.id,
                applied,
                verification,
                runner=_origin_runner(),
                http_client=fake.http(),
                push=FakePush(),
            )
        fake.queued = [
            httpx.Response(200, json={"default_branch": "main"}),
            httpx.Response(200, json=[]),
            httpx.Response(201, json={"html_url": "javascript:alert(1)", "number": 1}),
        ]
        with pytest.raises(PrError, match="unexpected pull request"):
            open_pull_request(
                db,
                settings,
                case.id,
                applied,
                verification,
                runner=_origin_runner(),
                http_client=fake.http(),
                push=FakePush(),
            )
    assert not fake.pulls


# --- records ------------------------------------------------------------------------------


def test_pull_request_of_audit_events(tmp_path):
    with Database(tmp_path / "g.db") as db:
        assert pull_request_of(db.audit.list("rc_x")) is None
        db.audit.append("rc_x", "pr:failed", "system", {"attempt": 1, "error": "no token"})
        assert pull_request_of(db.audit.list("rc_x"))["error"] == "no token"
        db.audit.append(
            "rc_x",
            "pr:opened",
            "system",
            {"url": "https://github.com/a/b/pull/3", "number": 3, "draft": True},
        )
        pr = pull_request_of(db.audit.list("rc_x"))
        assert (pr["url"], pr["number"], pr["draft"]) == ("https://github.com/a/b/pull/3", 3, True)
        db.audit.append("rc_y", "pr:opened", "system", {"url": "https://evil.example/x"})
        assert pull_request_of(db.audit.list("rc_y")) is None
    assert pr_url_is_safe("https://github.com/a/b/pull/1")
    assert not pr_url_is_safe("https://github.com/a b")
    assert not pr_url_is_safe('https://github.com/a"onmouseover=x')
    assert not pr_url_is_safe(None)

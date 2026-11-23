import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

import pytest

from guardian.analysis.git_diff import (
    ChangeAnalyzer,
    _newest_blame_commit,
    classify_commit,
    is_ci_config,
    is_manifest,
    is_secret_file,
    is_security_code,
    parse_log,
)
from guardian.core.config import GuardianSettings
from guardian.core.models import (
    ChangeCategory,
    ChangeRecord,
    CodeDetails,
    FileChange,
    Finding,
    FindingKind,
    Severity,
)
from guardian.core.profiler import RepositoryProfiler
from guardian.execution.runner import ToolRunner

requires_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


@pytest.mark.parametrize(
    ("path", "manifest", "ci", "secret", "security"),
    [
        ("package.json", True, False, False, False),
        ("requirements-dev.txt", True, False, False, False),
        ("services/api/pom.xml", True, False, False, False),
        (".github/workflows/ci.yml", False, True, False, False),
        (".gitlab-ci.yml", False, True, False, False),
        ("docs/.gitlab-ci.yml", False, False, False, False),
        (".env", False, False, True, False),
        ("deploy/server.pem", False, False, True, False),
        (".env.example", False, False, False, False),
        ("src/auth/login.py", False, False, False, True),
        ("docs/auth.md", False, False, False, False),
    ],
)
def test_path_classifiers(path, manifest, ci, secret, security):
    p = PurePosixPath(path)
    assert (is_manifest(p), is_ci_config(p), is_secret_file(p), is_security_code(p)) == (
        manifest,
        ci,
        secret,
        security,
    )


def test_parse_log():
    out = (
        "\x1eabc123\x1fAda\x1f2026-01-02T03:04:05+01:00\x1fBump deps\n\n"
        'M\tpackage-lock.json\nA\t"src/naïve.py"\n'
        "\x1edef456\x1f\x1f\x1f\n"
    )
    records = parse_log(out)
    assert [r.commit for r in records] == ["abc123", "def456"]
    first = records[0]
    assert first.author == "Ada"
    assert first.subject == "Bump deps"
    assert first.authored_at == datetime(2026, 1, 2, 2, 4, 5, tzinfo=UTC)
    assert first.files == [
        FileChange(path="package-lock.json", status="M"),
        FileChange(path="src/naïve.py", status="A"),
    ]
    assert records[1].author is None
    assert records[1].authored_at is None


def _record(*files: tuple[str, str]) -> ChangeRecord:
    return ChangeRecord(
        commit="a" * 40,
        author="Dev",
        subject="msg",
        files=[FileChange(path=p, status=s) for s, p in files],
    )


def _categories(findings):
    return {f.details.category: f for f in findings}


def test_lockfile_only_change(tmp_path):
    found = _categories(classify_commit(_record(("M", "web/package-lock.json")), tmp_path))
    lock = found[ChangeCategory.LOCKFILE_ONLY]
    assert lock.severity is Severity.LOW
    assert lock.details.paths == ["web/package-lock.json"]
    assert lock.introduced_by == "a" * 40


def test_lockfile_with_manifest_is_not_lockfile_only(tmp_path):
    record = _record(("M", "package.json"), ("M", "package-lock.json"))
    found = _categories(classify_commit(record, tmp_path))
    assert ChangeCategory.LOCKFILE_ONLY not in found
    assert found[ChangeCategory.MANIFEST].severity is Severity.INFO


def test_secret_file_severity_depends_on_presence(tmp_path):
    record = _record(("A", ".env"), ("A", "keys/id_rsa"))
    (tmp_path / ".env").write_text("X=1")
    findings = [
        f
        for f in classify_commit(record, tmp_path)
        if f.details.category is ChangeCategory.SENSITIVE_FILE
    ]
    by_path = {f.path: f for f in findings}
    assert by_path[".env"].severity is Severity.HIGH
    assert "still present" in by_path[".env"].title
    assert by_path["keys/id_rsa"].severity is Severity.MEDIUM


def test_ci_container_and_security_code(tmp_path):
    record = _record(
        ("M", ".github/workflows/release.yml"),
        ("M", "Dockerfile"),
        ("M", "src/session/tokens.ts"),
        ("D", "old/auth.py"),  # deletions are ignored
    )
    found = _categories(classify_commit(record, tmp_path))
    assert found[ChangeCategory.CI_CONFIG].severity is Severity.LOW
    assert found[ChangeCategory.CONTAINER].details.paths == ["Dockerfile"]
    assert found[ChangeCategory.SECURITY_CODE].details.paths == ["src/session/tokens.ts"]


def test_newest_blame_commit():
    sha_old, sha_new = "1" * 40, "2" * 40
    porcelain = (
        f"{sha_old} 1 1 1\nauthor Old\nauthor-time 1700000000\nauthor-tz +0000\nsummary first\n\tline\n"
        f"{sha_new} 2 2 1\nauthor New\nauthor-time 1800000000\nauthor-tz +0530\nsummary second\n\tline\n"
        f"{'0' * 40} 3 3 1\nauthor Not Committed Yet\nauthor-time 1900000000\n\tline\n"
    )
    record = _newest_blame_commit(porcelain)
    assert record.commit == sha_new
    assert record.author == "New"
    assert record.subject == "second"
    assert record.authored_at.utcoffset().total_seconds() == 5.5 * 3600
    assert _newest_blame_commit(f"{'0' * 40} 1 1 1\n\tx\n") is None


# --- against real git ----------------------------------------------------------------


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Dev",
            "-c",
            "user.email=dev@example.invalid",
            "-c",
            "core.autocrlf=false",
            *args,
        ],
        cwd=root,
        check=True,
        capture_output=True,
    )


@pytest.fixture
def history_repo(make_repo):
    root = make_repo({"package.json": "{}", "app.py": "import os\nos.system(cmd)\n"})
    _git(root, "init", "-q", "-b", "main")
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "initial")
    (root / "package-lock.json").write_text("{}")
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "lockfile only")
    (root / ".env").write_text("TOKEN=x\n")
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "add env")
    (root / "package.json").write_text('{"dependencies": {}}')  # uncommitted
    return root


def _analyzer_profile(root):
    profile = RepositoryProfiler(settings=GuardianSettings(_env_file=None)).profile(root)
    return ChangeAnalyzer(ToolRunner(), max_commits=10), profile


@requires_git
def test_analyze_real_history(history_repo):
    analyzer, profile = _analyzer_profile(history_repo)
    result = analyzer.analyze(profile)
    assert result.tool_run.status == "success"
    assert [c.subject for c in result.changes] == ["add env", "lockfile only", "initial"]
    categories = {f.details.category for f in result.findings}
    assert {
        ChangeCategory.SENSITIVE_FILE,
        ChangeCategory.LOCKFILE_ONLY,
        ChangeCategory.MANIFEST,
        ChangeCategory.UNCOMMITTED,
    } <= categories
    uncommitted = next(
        f for f in result.findings if f.details.category is ChangeCategory.UNCOMMITTED
    )
    assert uncommitted.details.commit is None
    assert uncommitted.details.paths == ["package.json"]


@requires_git
def test_blame_links_code_findings_to_commits(history_repo):
    analyzer, _ = _analyzer_profile(history_repo)
    code = Finding(
        id="f1",
        kind=FindingKind.CODE,
        title="os-system in app.py:2",
        severity=Severity.HIGH,
        tool="semgrep",
        path="app.py",
        start_line=2,
        end_line=2,
        details=CodeDetails(rule_id="r", message="m"),
    )
    other = code.model_copy(update={"id": "f2", "path": None, "start_line": None})
    updated, commits = analyzer.blame(history_repo, [code, other], limit=10)
    assert updated[0].introduced_by == commits[0].commit
    assert commits[0].subject == "initial"
    assert "last modified in" in updated[0].evidence[-1].summary
    assert updated[1] == other  # nothing to blame

    unblamed, none = analyzer.blame(history_repo, [code], limit=0)
    assert unblamed == [code]
    assert none == []


@requires_git
def test_skips_without_history(make_repo):
    root = make_repo({"a.py": ""})
    analyzer, profile = _analyzer_profile(root)
    assert analyzer.analyze(profile).tool_run.status == "skipped"  # not a repository
    _git(root, "init", "-q")
    analyzer, profile = _analyzer_profile(root)
    result = analyzer.analyze(profile)
    assert result.tool_run.status == "skipped"
    assert result.tool_run.error == "Repository has no commits"

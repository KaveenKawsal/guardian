"""Security-relevant change analysis from git history.

Signals produced (all deterministic, from ``git log`` / ``git status`` / ``git blame``):

* lockfile modified without its manifest: dependency tree changed with no declared reason,
  a classic place to slip in a malicious package version
* dependency manifests, CI/CD and container configuration changed
* secret-bearing files (.env, private keys, .npmrc ...) committed, flagged harder when the
  file is still present
* security-sensitive code (auth, crypto, sessions ...) changed
* uncommitted changes to manifests or lockfiles
* for code findings, the commit that last modified the flagged lines (INTRODUCED_BY)

Author emails are never collected, only display names.
"""

import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath

from guardian.adapters.container import COMPOSE_FILES, is_dockerfile
from guardian.adapters.java import BUILD_FILES as JAVA_BUILD_FILES
from guardian.adapters.java import LOCKFILES as JAVA_LOCKFILES
from guardian.adapters.node import LOCKFILES as NODE_LOCKFILES
from guardian.adapters.python import LOCKFILES as PYTHON_LOCKFILES
from guardian.analysis.base import AnalysisResult, skipped, stable_id, summarize
from guardian.core.models import (
    ChangeCategory,
    ChangeDetails,
    ChangeRecord,
    Evidence,
    EvidenceKind,
    FileChange,
    Finding,
    FindingKind,
    RepositoryProfile,
    Severity,
)
from guardian.core.profiler import CI_FILES, LANGUAGE_EXTENSIONS
from guardian.execution.results import ToolStatus
from guardian.execution.runner import ToolRunner

GIT = "git"
_RECORD, _FIELD = "\x1e", "\x1f"
LOG_FORMAT = f"{_RECORD}%H{_FIELD}%an{_FIELD}%aI{_FIELD}%s"
NULL_COMMIT = "0" * 40
MAX_PATHS_PER_FINDING = 20

LOCKFILE_NAMES = frozenset({*PYTHON_LOCKFILES, *NODE_LOCKFILES, *JAVA_LOCKFILES})
MANIFEST_NAMES = frozenset(
    {"pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "package.json", *JAVA_BUILD_FILES}
)
SECRET_FILE_NAMES = frozenset(
    {
        ".env",
        ".env.local",
        ".env.production",
        ".env.development",
        ".npmrc",
        ".pypirc",
        ".netrc",
        ".git-credentials",
        "credentials",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
    }
)
SECRET_FILE_SUFFIXES = frozenset({".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"})
SECURITY_CODE_PATTERN = re.compile(
    r"auth|login|passw|secret|token|crypt|jwt|oauth|session|permission|acl|security|sanitiz"
)


def is_manifest(path: PurePosixPath) -> bool:
    name = path.name
    return name in MANIFEST_NAMES or (name.startswith("requirements") and name.endswith(".txt"))


def is_ci_config(path: PurePosixPath) -> bool:
    parts = path.parts
    return (
        parts[:2] in {(".github", "workflows"), (".github", "actions")}
        or (parts[:1] == (".circleci",))
        or (len(parts) == 1 and path.name in CI_FILES)
    )


def is_secret_file(path: PurePosixPath) -> bool:
    name = path.name.lower()
    return name in SECRET_FILE_NAMES or path.suffix.lower() in SECRET_FILE_SUFFIXES


def is_security_code(path: PurePosixPath) -> bool:
    return path.suffix.lower() in LANGUAGE_EXTENSIONS and bool(
        SECURITY_CODE_PATTERN.search(path.as_posix().lower())
    )


def parse_log(stdout: str) -> list[ChangeRecord]:
    records = []
    for chunk in stdout.split(_RECORD)[1:]:
        header, _, body = chunk.partition("\n")
        sha, author, authored, subject = ([*header.split(_FIELD), "", "", ""])[:4]
        files = []
        for line in body.splitlines():
            status, sep, path = line.partition("\t")
            if sep and path:
                files.append(FileChange(path=path.strip().strip('"'), status=status[:1]))
        records.append(
            ChangeRecord(
                commit=sha.strip(),
                author=author or None,
                authored_at=datetime.fromisoformat(authored) if authored else None,
                subject=subject.strip() or None,
                files=files,
            )
        )
    return records


def _change_finding(  # noqa: PLR0913, PLR0917 - one parameter per finding field
    category: ChangeCategory,
    severity: Severity,
    title: str,
    record: ChangeRecord | None,
    paths: list[str],
    detail: str,
) -> Finding:
    paths = sorted(paths)[:MAX_PATHS_PER_FINDING]
    commit = record.commit if record else None
    where = f"commit {commit[:10]}" if commit else "the working tree"
    return Finding(
        id=stable_id(FindingKind.CHANGE, category, commit, ",".join(paths)),
        kind=FindingKind.CHANGE,
        title=title,
        severity=severity,
        tool=GIT,
        path=paths[0] if len(paths) == 1 else None,
        introduced_by=commit,
        details=ChangeDetails(
            category=category,
            commit=commit,
            author=record.author if record else None,
            authored_at=record.authored_at if record else None,
            subject=record.subject if record else None,
            paths=paths,
        ),
        evidence=[
            Evidence(
                kind=EvidenceKind.GIT_CHANGE,
                tool=GIT,
                summary=f"{detail} in {where}"
                + (f" by {record.author}: {record.subject}" if record and record.author else ""),
                commit=commit,
                path=paths[0] if len(paths) == 1 else None,
            )
        ],
    )


def classify_commit(record: ChangeRecord, repo_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    live = [f for f in record.files if f.status != "D"]
    paths = [PurePosixPath(f.path) for f in live]
    short = record.commit[:10]

    manifests = [p for p in paths if is_manifest(p)]
    manifest_dirs = {p.parent for p in manifests}
    lock_only = [p for p in paths if p.name in LOCKFILE_NAMES and p.parent not in manifest_dirs]
    if lock_only:
        findings.append(
            _change_finding(
                ChangeCategory.LOCKFILE_ONLY,
                Severity.LOW,
                f"Lockfile changed without its manifest in {short}",
                record,
                [str(p) for p in lock_only],
                "Resolved dependencies changed with no matching manifest change",
            )
        )
    if manifests:
        findings.append(
            _change_finding(
                ChangeCategory.MANIFEST,
                Severity.INFO,
                f"Dependency manifest changed in {short}",
                record,
                [str(p) for p in manifests],
                "Declared dependencies changed",
            )
        )
    if ci := [str(p) for p in paths if is_ci_config(p)]:
        findings.append(
            _change_finding(
                ChangeCategory.CI_CONFIG,
                Severity.LOW,
                f"CI/CD configuration changed in {short}",
                record,
                ci,
                "Build pipeline definition changed",
            )
        )
    containers = [str(p) for p in paths if is_dockerfile(p) or p.name.lower() in COMPOSE_FILES]
    if containers:
        findings.append(
            _change_finding(
                ChangeCategory.CONTAINER,
                Severity.INFO,
                f"Container configuration changed in {short}",
                record,
                containers,
                "Container build or composition changed",
            )
        )
    for path in (p for p in paths if is_secret_file(p)):
        still_present = (repo_root / path).is_file()
        findings.append(
            _change_finding(
                ChangeCategory.SENSITIVE_FILE,
                Severity.HIGH if still_present else Severity.MEDIUM,
                f"Secret-bearing file {path} committed in {short}"
                + (" (still present)" if still_present else " (since removed, remains in history)"),
                record,
                [str(path)],
                "A file that typically holds credentials was committed",
            )
        )
    if security := [str(p) for p in paths if is_security_code(p)]:
        findings.append(
            _change_finding(
                ChangeCategory.SECURITY_CODE,
                Severity.INFO,
                f"Security-sensitive code changed in {short}",
                record,
                security,
                "Authentication, authorization, crypto or session code changed",
            )
        )
    return findings


class ChangeAnalyzer:
    def __init__(self, runner: ToolRunner, max_commits: int = 50) -> None:
        self.runner = runner
        self.max_commits = max_commits

    def _git(self, root: Path, *args: str) -> tuple[bool, str, str]:
        result = self.runner.run(
            GIT, ["-c", "core.quotePath=false", *args], cwd=root, timeout_seconds=120
        )
        return result.status is ToolStatus.SUCCESS, result.stdout, result.error or result.stderr

    def analyze(self, profile: RepositoryProfile) -> AnalysisResult:
        if not profile.git.is_repository:
            return skipped(GIT, "Not a git repository")
        if profile.git.head_commit is None:
            return skipped(GIT, "Repository has no commits")
        root = Path(profile.root)

        log = self.runner.run(
            GIT,
            [
                "-c",
                "core.quotePath=false",  # print non-ASCII paths verbatim instead of octal-quoted
                "log",
                "--no-merges",
                "--no-renames",
                f"--max-count={self.max_commits}",
                f"--format={LOG_FORMAT}",
                "--name-status",
            ],
            cwd=root,
            timeout_seconds=120,
        )
        if log.status is not ToolStatus.SUCCESS:
            return AnalysisResult(tool_run=summarize(log))
        records = parse_log(log.stdout)
        findings = [f for record in records for f in classify_commit(record, root)]

        ok, status_out, _ = self._git(root, "status", "--porcelain", "--untracked-files=no")
        if ok:
            dirty = [
                line[3:].strip().strip('"')
                for line in status_out.splitlines()
                if len(line) > 3  # noqa: PLR2004
            ]
            dependency_paths = [
                p
                for p in dirty
                if is_manifest(PurePosixPath(p)) or PurePosixPath(p).name in LOCKFILE_NAMES
            ]
            if dependency_paths:
                findings.append(
                    _change_finding(
                        ChangeCategory.UNCOMMITTED,
                        Severity.INFO,
                        "Uncommitted dependency changes",
                        None,
                        dependency_paths,
                        "Manifests or lockfiles differ from the last commit",
                    )
                )
        return AnalysisResult(tool_run=summarize(log), findings=findings, changes=records)

    def blame(
        self, root: Path, findings: list[Finding], limit: int
    ) -> tuple[list[Finding], list[ChangeRecord]]:
        """Attach INTRODUCED_BY to code findings: the newest commit touching the flagged lines."""
        updated: list[Finding] = []
        commits: dict[str, ChangeRecord] = {}
        budget = limit
        for finding in findings:
            if finding.kind is not FindingKind.CODE or not finding.path or not finding.start_line:
                updated.append(finding)
                continue
            if budget <= 0:
                updated.append(finding)
                continue
            budget -= 1
            end = finding.end_line or finding.start_line
            ok, out, _ = self._git(
                root,
                "blame",
                "--porcelain",
                "-L",
                f"{finding.start_line},{end}",
                "--",
                finding.path,
            )
            record = _newest_blame_commit(out) if ok else None
            if record is None:
                updated.append(finding)
                continue
            commits.setdefault(record.commit, record)
            when = record.authored_at.date().isoformat() if record.authored_at else "unknown date"
            evidence = Evidence(
                kind=EvidenceKind.GIT_CHANGE,
                tool=GIT,
                summary=f"Flagged lines last modified in {record.commit[:10]} "
                f"by {record.author or 'unknown'} on {when}: {record.subject or ''}".rstrip(": "),
                commit=record.commit,
                path=finding.path,
                line=finding.start_line,
            )
            updated.append(
                finding.model_copy(
                    update={
                        "introduced_by": record.commit,
                        "evidence": [*finding.evidence, evidence],
                    }
                )
            )
        return updated, list(commits.values())


def _newest_blame_commit(porcelain: str) -> ChangeRecord | None:
    """Parse ``git blame --porcelain`` and return the most recently authored commit."""
    info: dict[str, dict[str, str]] = defaultdict(dict)
    current: str | None = None
    for line in porcelain.splitlines():
        head = line.split(" ", 1)[0]
        if len(head) == 40 and all(c in "0123456789abcdef" for c in head):  # noqa: PLR2004
            current = head
            continue
        if current and " " in line and not line.startswith("\t"):
            key, value = line.split(" ", 1)
            info[current].setdefault(key, value)
    candidates = [
        (int(meta.get("author-time", "0")), sha, meta)
        for sha, meta in info.items()
        if sha != NULL_COMMIT
    ]
    if not candidates:
        return None
    timestamp, sha, meta = max(candidates)
    return ChangeRecord(
        commit=sha,
        author=meta.get("author"),
        authored_at=_from_epoch(timestamp, meta.get("author-tz", "+0000")),
        subject=meta.get("summary"),
    )


def _from_epoch(timestamp: int, tz: str) -> datetime | None:
    """``author-time`` + ``author-tz`` (e.g. ``+0530``) from blame porcelain."""
    if not timestamp:
        return None
    try:
        sign = -1 if tz.startswith("-") else 1
        offset = timedelta(hours=int(tz[1:3]), minutes=int(tz[3:5])) * sign
    except ValueError:
        offset = timedelta(0)
    return datetime.fromtimestamp(timestamp, tz=timezone(offset))

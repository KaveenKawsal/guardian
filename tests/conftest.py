from collections.abc import Callable, Sequence
from pathlib import Path, PurePosixPath

import pytest

from guardian.adapters.base import RepositoryView
from guardian.analysis.base import AnalysisResult
from guardian.core.models import ChangeRecord, Finding, ToolRunSummary
from guardian.core.profiler import walk_repository

MakeRepo = Callable[[dict[str, str]], Path]  # 3.11-compatible alias (no `type` statement)


@pytest.fixture(autouse=True)
def _no_docker_lockfiles(monkeypatch):
    """Tests never start real containers: `guardian scan` would otherwise generate a missing
    npm lockfile in Docker. Tests that exercise the hook enable it explicitly."""
    monkeypatch.setenv("GUARDIAN_NPM_LOCKFILE_GENERATION", "false")


@pytest.fixture
def make_repo(tmp_path: Path) -> MakeRepo:
    """Create a repository from {relative_path: content} and return its root."""

    def _make(files: dict[str, str]) -> Path:
        root = tmp_path / "repo"
        root.mkdir(exist_ok=True)
        for rel, content in files.items():
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return root

    return _make


@pytest.fixture
def make_view(make_repo: MakeRepo) -> Callable[..., RepositoryView]:
    def _view(files: dict[str, str], max_read_bytes: int = 1024 * 1024) -> RepositoryView:
        root = make_repo(files)
        walk = walk_repository(root, frozenset({".git", "node_modules"}), max_files=10_000)
        return RepositoryView(
            root=root,
            files=tuple(PurePosixPath(f) for f in walk.files),
            max_read_bytes=max_read_bytes,
        )

    return _view


class StubAnalyzer:
    """Stands in for OsvScanner, SemgrepScanner and ChangeAnalyzer (duck-typed)."""

    def __init__(self, result: AnalysisResult, blamed_commit: str | None = None) -> None:
        self.result = result
        self.blamed_commit = blamed_commit
        self.calls = 0
        self.blame_calls = 0

    def scan(self, *args: object, **kwargs: object) -> AnalysisResult:
        self.calls += 1
        if isinstance(self.result, Exception):
            raise self.result
        return self.result

    analyze = scan

    def blame(self, root: Path, findings: list[Finding], limit: int):
        self.blame_calls += 1
        if not self.blamed_commit:
            return findings, []
        updated = [
            f.model_copy(update={"introduced_by": self.blamed_commit}) if f.path else f
            for f in findings
        ]
        return updated, [ChangeRecord(commit=self.blamed_commit, author="Dev")]


def analysis(
    tool: str,
    findings: Sequence[Finding] = (),
    status: str = "success",
    changes: Sequence[ChangeRecord] = (),
    warnings: Sequence[str] = (),
) -> AnalysisResult:
    return AnalysisResult(
        tool_run=ToolRunSummary(tool=tool, status=status),
        findings=list(findings),
        changes=list(changes),
        warnings=list(warnings),
    )


@pytest.fixture
def stubs() -> dict[str, StubAnalyzer]:
    """Analyzers that report nothing, so pipeline tests never reach the network."""
    return {
        "osv_scanner": StubAnalyzer(analysis("osv-scanner")),
        "semgrep_scanner": StubAnalyzer(analysis("semgrep")),
        "change_analyzer": StubAnalyzer(analysis("git", status="skipped")),
    }

"""Deterministic scan pipeline.

    profile -> SBOM (cdxgen) -> CycloneDX normalization
            -> [ OSV-Scanner | Semgrep | git change analysis ]   (concurrent, thread pool)
               + source indexing (Tree-sitter)                   (main thread, meanwhile)
            -> git blame for code findings -> code-context enrichment
            -> knowledge graph -> persist

Every analysis step degrades to a warning plus a recorded tool run, so a missing or failing
tool yields a PARTIAL scan instead of no scan. Phase 5 wraps these steps as LangGraph nodes.
"""

import tempfile
import time
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from guardian.analysis.base import AnalysisResult, skipped, summarize
from guardian.analysis.cyclonedx import SbomParseError, parse_cyclonedx
from guardian.analysis.git_diff import GIT, ChangeAnalyzer
from guardian.analysis.osv import OSV_SCANNER, OsvScanner
from guardian.analysis.sbom import CDXGEN, SbomGenerator
from guardian.analysis.semgrep import SEMGREP, SemgrepScanner
from guardian.core.config import GuardianSettings
from guardian.core.exceptions import GuardianError
from guardian.core.models import (
    ChangeRecord,
    CodeIndex,
    Finding,
    RepositoryProfile,
    Sbom,
    ScanRecord,
    ScanStatus,
    ToolRunSummary,
)
from guardian.core.profiler import RepositoryProfiler
from guardian.execution.policies import ExecutionPolicy
from guardian.execution.results import ToolStatus
from guardian.execution.runner import ToolRunner
from guardian.indexing.enrichment import add_usage_evidence, attach_symbols
from guardian.indexing.repository_indexer import EXTRACT_ERROR, RepositoryIndexer
from guardian.knowledge.graph_builder import build_knowledge_graph
from guardian.knowledge.graph_queries import DependencyGraph
from guardian.storage.database import Database

_OK_STATUSES = frozenset({ToolStatus.SUCCESS.value, ToolStatus.SKIPPED.value})
INDEXER = "indexer"


@dataclass(frozen=True)
class ScanOutcome:
    record: ScanRecord
    profile: RepositoryProfile
    sbom: Sbom | None
    graph: DependencyGraph
    findings: list[Finding] = field(default_factory=list)
    changes: list[ChangeRecord] = field(default_factory=list)
    code_index: CodeIndex | None = None
    """None when indexing was disabled, found no source files or failed."""


@dataclass
class _StepLog:
    tool_runs: list[ToolRunSummary] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def absorb(self, result: AnalysisResult) -> None:
        self.tool_runs.append(result.tool_run)
        self.warnings += result.warnings


class ScanPipeline:
    def __init__(  # noqa: PLR0913 - every analyzer is injectable for tests
        self,
        db: Database,
        settings: GuardianSettings | None = None,
        *,
        profiler: RepositoryProfiler | None = None,
        sbom_generator: SbomGenerator | None = None,
        osv_scanner: OsvScanner | None = None,
        semgrep_scanner: SemgrepScanner | None = None,
        change_analyzer: ChangeAnalyzer | None = None,
        indexer: RepositoryIndexer | None = None,
    ) -> None:
        self.db = db
        self.settings = s = settings or GuardianSettings()
        runner = ToolRunner(
            ExecutionPolicy(
                timeout_seconds=s.tool_timeout_seconds, max_output_bytes=s.max_tool_output_bytes
            )
        )
        self.profiler = profiler or RepositoryProfiler(s, runner=runner)
        self.sbom_generator = sbom_generator or SbomGenerator(runner)
        self.osv_scanner = osv_scanner or OsvScanner(runner)
        self.semgrep_scanner = semgrep_scanner or SemgrepScanner(
            runner, configs=s.semgrep_configs, rule_timeout_seconds=s.semgrep_rule_timeout_seconds
        )
        self.change_analyzer = change_analyzer or ChangeAnalyzer(runner, s.change_history_commits)
        # The cache reads/writes through the SQLite connection, so indexing stays on the
        # thread that created ``db`` (the caller's thread).
        self.indexer = indexer or RepositoryIndexer(s, cache=db.code.cache())

    def run(self, path: Path) -> ScanOutcome:
        started = datetime.now(UTC)
        profile = self.profiler.profile(path)  # invalid paths fail before anything is stored

        scan_id = uuid.uuid4().hex
        repository_id = self.db.repositories.upsert(profile.root, profile.name)
        self.db.scans.create(scan_id, repository_id, started, profile)

        log = _StepLog(warnings=list(profile.warnings))
        log.warnings += [w for e in profile.ecosystems for w in e.warnings]
        try:
            sbom, raw = self._dependency_stage(profile, log)
            if sbom is not None:
                self.db.sboms.save(scan_id, sbom, raw)
            findings, changes, code_index = self._security_stage(profile, sbom, raw, log)
            if code_index is not None:
                self.db.code.save(scan_id, code_index)
            self.db.findings.save(scan_id, findings, changes)
            graph = DependencyGraph(
                build_knowledge_graph(profile, sbom, findings, changes, code_index=code_index)
            )
        except BaseException:
            self._finish(scan_id, ScanStatus.FAILED, log, component_count=0, finding_count=0)
            raise

        tools_ok = all(t.status in _OK_STATUSES for t in log.tool_runs)
        sbom_missing = bool(profile.ecosystems) and sbom is None
        status = ScanStatus.COMPLETED if tools_ok and not sbom_missing else ScanStatus.PARTIAL
        self._finish(
            scan_id,
            status,
            log,
            component_count=len(sbom.components) if sbom else 0,
            finding_count=len(findings),
        )
        return ScanOutcome(
            record=self.db.scans.get(scan_id),
            profile=profile,
            sbom=sbom,
            graph=graph,
            findings=findings,
            changes=changes,
            code_index=code_index,
        )

    def _finish(
        self,
        scan_id: str,
        status: ScanStatus,
        log: _StepLog,
        *,
        component_count: int,
        finding_count: int,
    ) -> None:
        self.db.scans.finish(
            scan_id,
            status=status,
            finished_at=datetime.now(UTC),
            tool_runs=log.tool_runs,
            warnings=log.warnings,
            component_count=component_count,
            finding_count=finding_count,
        )

    # --- dependency intelligence -------------------------------------------------------

    def _dependency_stage(
        self, profile: RepositoryProfile, log: _StepLog
    ) -> tuple[Sbom | None, bytes | None]:
        if not profile.ecosystems:
            log.absorb(skipped(CDXGEN, "No supported dependency manifests found"))
            return None, None

        with tempfile.TemporaryDirectory(prefix="guardian-sbom-") as work_dir:
            try:
                generation = self.sbom_generator.generate(Path(profile.root), Path(work_dir))
            except GuardianError as exc:  # e.g. an argument the runner refuses to pass
                log.tool_runs.append(
                    ToolRunSummary(tool=CDXGEN, status=ToolStatus.ERROR.value, error=str(exc))
                )
                log.warnings.append(f"SBOM generation skipped: {exc}")
                return None, None

            log.tool_runs.append(summarize(generation.result))
            log.warnings += generation.warnings
            if generation.bom_path is None:
                reason = log.tool_runs[-1].error or "no output"
                log.warnings.append(f"No SBOM produced; dependency analysis skipped ({reason})")
                return None, None

            size = generation.bom_path.stat().st_size
            if size > self.settings.max_sbom_bytes:
                log.warnings.append(
                    f"SBOM is {size} bytes, above the {self.settings.max_sbom_bytes} byte limit"
                )
                return None, None
            raw = generation.bom_path.read_bytes()

        try:
            sbom = parse_cyclonedx(
                raw,
                repo_root=Path(profile.root),
                manifests=profile.manifest_paths,
                declared=profile.declared_dependencies,
            )
        except SbomParseError as exc:
            log.warnings.append(str(exc))
            return None, raw
        log.warnings += sbom.warnings
        return sbom, raw

    # --- security detection ------------------------------------------------------------

    def _security_stage(
        self,
        profile: RepositoryProfile,
        sbom: Sbom | None,
        raw_sbom: bytes | None,
        log: _StepLog,
    ) -> tuple[list[Finding], list[ChangeRecord], CodeIndex | None]:
        root = Path(profile.root)
        excluded = self.settings.excluded_dirs
        with tempfile.TemporaryDirectory(prefix="guardian-scan-") as tmp:
            osv_dir, semgrep_dir = Path(tmp, "osv"), Path(tmp, "semgrep")
            osv_dir.mkdir()
            semgrep_dir.mkdir()

            tasks: dict[str, Callable[[], AnalysisResult]] = {
                OSV_SCANNER: (
                    (lambda: self.osv_scanner.scan(root, osv_dir, sbom, raw_sbom, excluded))
                    if profile.ecosystems
                    else (lambda: skipped(OSV_SCANNER, "No supported dependency manifests found"))
                ),
                SEMGREP: lambda: self.semgrep_scanner.scan(profile, semgrep_dir, excluded),
                GIT: lambda: self.change_analyzer.analyze(profile),
            }
            # The analyzers are independent subprocess-bound tools, so they run concurrently.
            # Indexing runs meanwhile on this thread: its cache uses the SQLite connection.
            with ThreadPoolExecutor(max_workers=len(tasks)) as pool:
                futures = {name: pool.submit(task) for name, task in tasks.items()}
                code_index, index_run, index_warnings = self._index_stage(profile, sbom)
                results = {
                    name: _result_or_error(name, future.result) for name, future in futures.items()
                }

        findings: list[Finding] = []
        changes: list[ChangeRecord] = []
        for result in results.values():  # deterministic order: osv, semgrep, git
            log.absorb(result)
            findings += result.findings
            changes += result.changes
        log.tool_runs.append(index_run)
        log.warnings += index_warnings

        git_ran = results[GIT].tool_run.status == ToolStatus.SUCCESS.value
        if git_ran and self.settings.max_blamed_findings:
            findings, blamed = self.change_analyzer.blame(
                root, findings, self.settings.max_blamed_findings
            )
            known = {c.commit for c in changes}
            changes += [c for c in blamed if c.commit not in known]

        if code_index is not None:
            findings = add_usage_evidence(attach_symbols(findings, code_index), code_index)

        unique = {f.id: f for f in findings}
        ordered = sorted(unique.values(), key=lambda f: (-f.severity.rank, f.kind, f.title))
        return ordered, changes, code_index

    # --- codebase understanding --------------------------------------------------------

    def _index_stage(
        self, profile: RepositoryProfile, sbom: Sbom | None
    ) -> tuple[CodeIndex | None, ToolRunSummary, list[str]]:
        """Index the source. Returns the index (None unless it has files), the tool run and
        warnings. Never raises for indexer bugs: the scan continues without an index."""
        if not self.settings.index_source:
            reason = "Source indexing disabled (index_source=false)"
            return None, _index_run(ToolStatus.SKIPPED, 0.0, reason), []
        started = time.monotonic()
        try:
            index = self.indexer.index(profile, sbom)
        except Exception as exc:  # noqa: BLE001 - a partial scan beats no scan
            elapsed = time.monotonic() - started
            message = f"{type(exc).__name__}: {exc}"
            warning = f"Source indexing failed; continuing without a code index ({message})"
            return None, _index_run(ToolStatus.ERROR, elapsed, message), [warning]
        elapsed = time.monotonic() - started

        warnings = list(index.warnings)
        if failed := index.skipped_files.get(EXTRACT_ERROR, 0):
            warnings.append(f"Source indexing: {failed} file(s) could not be parsed")
        if not index.files:
            run = _index_run(ToolStatus.SKIPPED, elapsed, "No supported source files indexed")
            return None, run, warnings
        return index, _index_run(ToolStatus.SUCCESS, elapsed), warnings


def _index_run(status: ToolStatus, elapsed: float, error: str | None = None) -> ToolRunSummary:
    return ToolRunSummary(
        tool=INDEXER, status=status.value, duration_seconds=round(elapsed, 3), error=error
    )


def _result_or_error(name: str, get: Callable[[], AnalysisResult]) -> AnalysisResult:
    """Expected Guardian errors (e.g. refused arguments) become an errored tool run."""
    try:
        return get()
    except GuardianError as exc:
        return AnalysisResult(
            tool_run=ToolRunSummary(tool=name, status=ToolStatus.ERROR.value, error=str(exc)),
            warnings=[f"{name} did not run: {exc}"],
        )

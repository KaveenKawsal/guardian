"""Deterministic scan pipeline.

    profile -> SBOM (cdxgen) -> CycloneDX normalization
            -> [ OSV-Scanner | Semgrep | git change analysis ]   (concurrent)
            -> git blame for code findings -> knowledge graph -> persist

Every analysis step degrades to a warning plus a recorded tool run, so a missing or failing
tool yields a PARTIAL scan instead of no scan. Phase 5 wraps these steps as LangGraph nodes.
"""

import tempfile
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
from guardian.knowledge.graph_builder import build_knowledge_graph
from guardian.knowledge.graph_queries import DependencyGraph
from guardian.storage.database import Database

_OK_STATUSES = frozenset({ToolStatus.SUCCESS.value, ToolStatus.SKIPPED.value})


@dataclass(frozen=True)
class ScanOutcome:
    record: ScanRecord
    profile: RepositoryProfile
    sbom: Sbom | None
    graph: DependencyGraph
    findings: list[Finding] = field(default_factory=list)
    changes: list[ChangeRecord] = field(default_factory=list)


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
            findings, changes = self._security_stage(profile, sbom, raw, log)
            self.db.findings.save(scan_id, findings, changes)
            graph = DependencyGraph(build_knowledge_graph(profile, sbom, findings, changes))
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
    ) -> tuple[list[Finding], list[ChangeRecord]]:
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
            with ThreadPoolExecutor(max_workers=len(tasks)) as pool:
                futures = {name: pool.submit(task) for name, task in tasks.items()}
                results = {
                    name: _result_or_error(name, future.result) for name, future in futures.items()
                }

        findings: list[Finding] = []
        changes: list[ChangeRecord] = []
        for result in results.values():  # deterministic order: osv, semgrep, git
            log.absorb(result)
            findings += result.findings
            changes += result.changes

        git_ran = results[GIT].tool_run.status == ToolStatus.SUCCESS.value
        if git_ran and self.settings.max_blamed_findings:
            findings, blamed = self.change_analyzer.blame(
                root, findings, self.settings.max_blamed_findings
            )
            known = {c.commit for c in changes}
            changes += [c for c in blamed if c.commit not in known]

        unique = {f.id: f for f in findings}
        ordered = sorted(unique.values(), key=lambda f: (-f.severity.rank, f.kind, f.title))
        return ordered, changes


def _result_or_error(name: str, get: Callable[[], AnalysisResult]) -> AnalysisResult:
    """Expected Guardian errors (e.g. refused arguments) become an errored tool run."""
    try:
        return get()
    except GuardianError as exc:
        return AnalysisResult(
            tool_run=ToolRunSummary(tool=name, status=ToolStatus.ERROR.value, error=str(exc)),
            warnings=[f"{name} did not run: {exc}"],
        )

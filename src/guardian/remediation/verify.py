"""Rescan the fix worktree, compare before/after and give the verdict.

Verdict (evaluated in this order):

1. UNVERIFIED: the rescan did not run, failed, or cdxgen/OSV-Scanner did not succeed (we
   cannot tell whether the findings are resolved).
2. FAILED: a target finding is still present, a new HIGH/CRITICAL finding appeared, the
   dependency install or build failed/timed out, or tests failed for real.
3. UNVERIFIED: no sandbox was available, or validation did not run at all.
4. PARTIALLY_VERIFIED: resolved and built (or no build step), but no tests were found, only
   new LOW/MEDIUM/unknown findings appeared, the only test failures are known conflicts with
   intentional challenge code ("fix conflicts with intentional challenge code"), or the
   validation ran on the host (``host-unsafe`` is capped here).
5. VERIFIED: targets resolved, nothing new at HIGH/CRITICAL, build passed, tests ran and
   passed, all inside the Docker sandbox.

Confidence follows what actually ran: Docker + tests passed + complete rescan -> high; a usable
rescan plus an install that ran -> medium; anything less -> low.

``run_remediation`` is the CLI fallback until the LangGraph remediation graph lands. It moves
the case APPROVED/MODIFICATION_REQUESTED -> APPLYING -> VALIDATING -> VERIFIED or
VALIDATION_FAILED. Only a VERIFIED verdict maps to the VERIFIED status; PARTIALLY_VERIFIED,
UNVERIFIED and FAILED all map to VALIDATION_FAILED, which sends the case back to a human.
"""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from guardian.core.config import GuardianSettings
from guardian.core.exceptions import GuardianError
from guardian.core.models import Confidence, Finding, ScanRecord, ScanStatus, Severity
from guardian.core.remediation_models import (
    CaseStatus,
    HumanDecision,
    RemediationCandidate,
    RemediationCase,
    StepStatus,
    ValidationRun,
    ValidationStep,
    VerificationResult,
    VerificationStatus,
)
from guardian.execution.results import ToolStatus
from guardian.execution.runner import ToolRunner
from guardian.knowledge.graph_builder import build_knowledge_graph
from guardian.knowledge.graph_queries import DependencyGraph
from guardian.knowledge.risk import assess
from guardian.remediation.apply import AppliedChange, ApplyFn, apply_case
from guardian.remediation.diff import diff_findings, diff_sboms
from guardian.remediation.sandbox import Sandbox, SandboxConfig
from guardian.remediation.testparse import KNOWN_CONFLICT_DETAIL
from guardian.remediation.validate import validate_case
from guardian.storage.database import Database
from guardian.storage.remediation import SYSTEM_ACTOR

ScanFn = Callable[[Path], str]
"""``scan_fn(worktree) -> after_scan_id``."""

REQUIRED_SCANNERS: tuple[str, ...] = ("cdxgen", "osv-scanner")
HIGH_SEVERITIES = frozenset({Severity.HIGH, Severity.CRITICAL})
_BAD_STEP = frozenset({StepStatus.FAILED, StepStatus.TIMEOUT})


def default_scan_fn(
    db: Database,
    settings: GuardianSettings | None = None,
    *,
    lockfile_generator: Callable[[Path, Path], tuple[Path | None, str | None]] | None = None,
) -> ScanFn:
    """Rescan with the regular ``ScanPipeline``. The worktree has no lockfile either, so pass
    the same lockfile generator the original scan used."""

    def scan(path: Path) -> str:
        from guardian.orchestration.pipeline import ScanPipeline  # noqa: PLC0415 - avoid cycle

        pipeline = ScanPipeline(db, settings, lockfile_generator=lockfile_generator)
        return pipeline.run(path).record.id

    return scan


# --- verdict ----------------------------------------------------------------------------


@dataclass(frozen=True)
class VerdictInputs:
    validation: ValidationRun
    after_scan: ScanRecord | None
    still_present: Sequence[str] = ()
    resolved: Sequence[str] = ()
    new_findings: Sequence[Finding] = ()
    scan_error: str | None = None


def _scan_problem(after: ScanRecord | None, scan_error: str | None) -> str | None:
    if after is None:
        return f"rescan did not run: {scan_error or 'no scan id'}"
    if after.status is ScanStatus.FAILED:
        return "rescan failed"
    runs = {t.tool: t.status for t in after.tool_runs}
    missing = [t for t in REQUIRED_SCANNERS if runs.get(t) != ToolStatus.SUCCESS.value]
    if missing:
        detail = ", ".join(f"{t}={runs.get(t, 'not run')}" for t in missing)
        return f"rescan incomplete: required scanner(s) did not succeed ({detail})"
    return None


def _failures(inputs: VerdictInputs, steps: Mapping[str, ValidationStep]) -> list[str]:
    failures: list[str] = []
    if inputs.still_present:
        failures.append(f"target finding(s) still present: {', '.join(inputs.still_present)}")
    new_high = [f for f in inputs.new_findings if f.severity in HIGH_SEVERITIES]
    if new_high:
        ids = ", ".join(f"{f.id} ({f.severity.value})" for f in new_high)
        failures.append(f"new HIGH/CRITICAL finding(s) introduced: {ids}")
    install, build, test = steps.get("install"), steps.get("build"), steps.get("test")
    if install and install.status in _BAD_STEP:
        failures.append(f"dependency install {install.status.value}: {install.detail or ''}")
    if build and build.status in _BAD_STEP:
        failures.append(f"build {build.status.value}: {build.detail or ''}")
    if test and test.status in _BAD_STEP and not test.known_conflict:
        failures.append(f"tests {test.status.value}: {test.detail or ''}")
    return [f.rstrip(": ") for f in failures]


def _partials(inputs: VerdictInputs, steps: Mapping[str, ValidationStep]) -> list[str]:
    partial: list[str] = []
    build, test = steps.get("build"), steps.get("test")
    if build is None or build.status is not StepStatus.PASSED:
        partial.append(f"no build step ran ({build.detail if build else 'none'})")
    if test is None or test.status in {StepStatus.NOT_FOUND, StepStatus.SKIPPED}:
        partial.append(f"no tests found ({test.detail if test else 'none'})")
    elif test.known_conflict:
        partial.append(f"{KNOWN_CONFLICT_DETAIL}: {test.detail or ''}".rstrip(": "))
    other = [f for f in inputs.new_findings if f.severity not in HIGH_SEVERITIES]
    if other:
        ids = ", ".join(f"{f.id} ({f.severity.value})" for f in other)
        partial.append(f"new lower-severity finding(s) introduced: {ids}")
    if inputs.validation.sandbox == "host-unsafe":
        partial.append(
            "validated on the host without a sandbox (--unsafe-host-validation); "
            "capped at PARTIALLY_VERIFIED"
        )
    return partial


def _confidence(
    inputs: VerdictInputs, steps: Mapping[str, ValidationStep], *, scan_ok: bool
) -> Confidence:
    test, install = steps.get("test"), steps.get("install")
    tests_passed = (
        test is not None
        and test.status is StepStatus.PASSED
        and inputs.validation.tests_discovered != 0
    )
    complete = inputs.after_scan is not None and inputs.after_scan.status is ScanStatus.COMPLETED
    if inputs.validation.sandbox == "docker" and tests_passed and complete:
        return Confidence.HIGH
    if scan_ok and install is not None and install.status is StepStatus.PASSED:
        return Confidence.MEDIUM
    return Confidence.LOW


def decide_verdict(inputs: VerdictInputs) -> tuple[VerificationStatus, Confidence, list[str]]:
    """Pure verdict function; see the module docstring for the rules."""
    steps: dict[str, ValidationStep] = {s.name: s for s in inputs.validation.steps}
    problem = _scan_problem(inputs.after_scan, inputs.scan_error)
    if problem:
        return VerificationStatus.UNVERIFIED, Confidence.LOW, [problem]

    reasons: list[str] = []
    if inputs.resolved and not inputs.still_present:
        reasons.append(f"all target findings resolved: {', '.join(inputs.resolved)}")
    confidence = _confidence(inputs, steps, scan_ok=True)
    failures = _failures(inputs, steps)
    if failures:
        return VerificationStatus.FAILED, confidence, reasons + failures

    if inputs.validation.sandbox == "none":
        install = steps.get("install")
        detail = install.detail if install and install.detail else "sandbox unavailable"
        return VerificationStatus.UNVERIFIED, Confidence.LOW, [*reasons, detail]
    install = steps.get("install")
    if install is None or install.status is not StepStatus.PASSED:
        detail = install.detail if install else "no install step"
        return (
            VerificationStatus.UNVERIFIED,
            Confidence.LOW,
            [
                *reasons,
                f"validation did not run: {detail}",
            ],
        )

    build, test = steps.get("build"), steps.get("test")
    if build is not None and build.status is StepStatus.PASSED:
        reasons.append(f"build passed ({build.detail or 'ok'})")
    if test is not None and test.status is StepStatus.PASSED:
        reasons.append(f"tests passed ({test.detail or 'ok'})")
    partial = _partials(inputs, steps)
    if partial:
        return VerificationStatus.PARTIALLY_VERIFIED, confidence, reasons + partial
    reasons.append("no new HIGH/CRITICAL findings; validated in the Docker sandbox")
    return VerificationStatus.VERIFIED, confidence, reasons


# --- risk -------------------------------------------------------------------------------


def max_risk(db: Database, scan_id: str, finding_ids: Sequence[str]) -> float | None:
    """Highest risk score among ``finding_ids`` in ``scan_id`` (None when none is scored)."""
    wanted = set(finding_ids)
    findings = db.findings.load(scan_id)
    targets = [f for f in findings if f.id in wanted]
    if not targets:
        return None
    profile = db.scans.profile(scan_id)
    code_index = db.code.load(scan_id)
    graph = DependencyGraph(
        build_knowledge_graph(
            profile,
            db.sboms.load(scan_id),
            findings,
            db.findings.changes(scan_id),
            code_index=code_index,
        )
    )
    scores = [a.score for a in assess(targets, graph, code_index) if a.score is not None]
    return max(scores) if scores else None


# --- verification -----------------------------------------------------------------------


def verify_case(  # noqa: PLR0913 - every collaborator is injectable for tests
    db: Database,
    case: RemediationCase,
    applied: AppliedChange,
    validation: ValidationRun,
    *,
    before_scan_id: str,
    scan_fn: ScanFn,
    actor: str = SYSTEM_ACTOR,
) -> VerificationResult:
    """Rescan the worktree, diff against ``before_scan_id``, decide, save and audit."""
    after_scan_id: str | None = None
    scan_error: str | None = None
    try:
        after_scan_id = scan_fn(applied.worktree_path)
    except Exception as exc:  # noqa: BLE001 - a failed rescan is an UNVERIFIED verdict
        scan_error = f"{type(exc).__name__}: {exc}"

    before = db.findings.load(before_scan_id)
    after = db.findings.load(after_scan_id) if after_scan_id else []
    after_record = db.scans.get(after_scan_id) if after_scan_id else None
    targets = list(case.finding_ids)
    after_ids = {f.id for f in after}
    _, _, new_ids = diff_findings(before, after)
    new_findings = [f for f in after if f.id in set(new_ids)]
    if after_record is not None:
        resolved = [t for t in targets if t not in after_ids]
        still_present = [t for t in targets if t in after_ids]
    else:
        resolved, still_present = [], []

    status, confidence, reasons = decide_verdict(
        VerdictInputs(
            validation=validation,
            after_scan=after_record,
            still_present=still_present,
            resolved=resolved,
            new_findings=new_findings,
            scan_error=scan_error,
        )
    )
    risk_before = _safe_risk(db, before_scan_id, targets)
    risk_after = None
    if after_scan_id:
        risk_after = _safe_risk(db, after_scan_id, still_present) if still_present else 0.0
    result = VerificationResult(
        case_id=case.id,
        before_scan_id=before_scan_id,
        after_scan_id=after_scan_id,
        target_findings_resolved=resolved,
        findings_still_present=still_present,
        new_findings=sorted(new_ids),
        sbom_diff=diff_sboms(
            db.sboms.load(before_scan_id), db.sboms.load(after_scan_id) if after_scan_id else None
        ),
        risk_before=risk_before,
        risk_after=risk_after,
        status=status,
        confidence=confidence,
        reasons=reasons,
    )
    db.remediation.save_verification(result)
    db.audit.append(
        case.id,
        "verify:finished",
        actor,
        {
            "status": result.status.value,
            "confidence": result.confidence.value,
            "after_scan_id": after_scan_id,
            "resolved": resolved,
            "still_present": still_present,
            "new_findings": result.new_findings,
            "risk_before": risk_before,
            "risk_after": risk_after,
        },
    )
    return result


def _safe_risk(db: Database, scan_id: str, finding_ids: Sequence[str]) -> float | None:
    try:
        return max_risk(db, scan_id, finding_ids)
    except GuardianError:
        return None


# --- CLI fallback driver ----------------------------------------------------------------


@dataclass(frozen=True)
class RemediationRun:
    case: RemediationCase
    applied: AppliedChange | None = None
    validation: ValidationRun | None = None
    verification: VerificationResult | None = None
    errors: list[str] = field(default_factory=list)


def run_remediation(  # noqa: PLR0913 - every collaborator is injectable for tests
    db: Database,
    case: RemediationCase,
    decision: HumanDecision,
    *,
    repo_root: Path,
    guardian_home: Path,
    runner: ToolRunner,
    sandbox: Sandbox,
    scan_fn: ScanFn,
    candidate: RemediationCandidate | None = None,
    apply_fn: ApplyFn | None = None,
    config: SandboxConfig | None = None,
    unsafe_host: bool = False,
    host_sandbox: Sandbox | None = None,
    actor: str = SYSTEM_ACTOR,
) -> RemediationRun:
    """Apply -> validate -> verify with case status transitions (see module docstring)."""
    case = db.remediation.update_status(case.id, CaseStatus.APPLYING, actor=actor)
    try:
        applied = apply_case(
            db,
            case,
            candidate,
            decision,
            repo_root=repo_root,
            guardian_home=guardian_home,
            runner=runner,
            apply_fn=apply_fn,
            actor=actor,
        )
    except GuardianError as exc:
        case = db.remediation.update_status(
            case.id, CaseStatus.VALIDATION_FAILED, actor=actor, payload={"error": str(exc)}
        )
        return RemediationRun(case=case, errors=[str(exc)])

    case = db.remediation.update_status(
        case.id, CaseStatus.VALIDATING, actor=actor, payload={"commit": applied.commit_sha}
    )
    validation = validate_case(
        db,
        case,
        applied,
        sandbox=sandbox,
        config=config,
        unsafe_host=unsafe_host,
        host_sandbox=host_sandbox,
        log_root=guardian_home / "logs",
        actor=actor,
    )
    verification = verify_case(
        db,
        case,
        applied,
        validation,
        before_scan_id=case.scan_id,
        scan_fn=scan_fn,
        actor=actor,
    )
    verified = verification.status is VerificationStatus.VERIFIED
    final = CaseStatus.VERIFIED if verified else CaseStatus.VALIDATION_FAILED
    case = db.remediation.update_status(
        case.id,
        final,
        actor=actor,
        payload={"verdict": verification.status.value, "reasons": verification.reasons},
    )
    return RemediationRun(
        case=case, applied=applied, validation=validation, verification=verification
    )

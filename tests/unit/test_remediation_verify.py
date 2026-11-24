# ruff: noqa: RUF001, SLF001, EM101, TRY003 - U+2139 is real reporter output; test doubles
from datetime import UTC, datetime
from pathlib import Path

import pytest
from remediation_fakes import (
    T0,
    FakeSandbox,
    bump_lodash,
    decision,
    git,
    init_repo,
    make_candidate,
    make_case,
    make_scan,
    save_plan,
    sbom_with,
    vuln,
)

from guardian.core.models import (
    Confidence,
    ScanRecord,
    ScanStatus,
    Severity,
    ToolRunSummary,
)
from guardian.core.remediation_models import (
    CaseStatus,
    StepStatus,
    ValidationRun,
    ValidationStep,
    VerificationStatus,
)
from guardian.execution.policies import ExecutionPolicy
from guardian.execution.runner import ToolRunner
from guardian.remediation import verify as verify_module
from guardian.remediation.apply import AppliedChange
from guardian.remediation.sandbox import StepResult
from guardian.remediation.verify import (
    VerdictInputs,
    decide_verdict,
    default_scan_fn,
    max_risk,
    run_remediation,
    verify_case,
)
from guardian.storage.database import Database

OK_RUNS = [
    ToolRunSummary(tool="cdxgen", status="success"),
    ToolRunSummary(tool="osv-scanner", status="success"),
]

P, F, S, N, T = (
    StepStatus.PASSED,
    StepStatus.FAILED,
    StepStatus.SKIPPED,
    StepStatus.NOT_FOUND,
    StepStatus.TIMEOUT,
)


def _run(sandbox="docker", install=P, build=P, test=P, *, known=False, discovered=5):
    return ValidationRun(
        case_id="rc_1",
        branch="guardian/fix-rc_1",
        worktree_path="/w",
        sandbox=sandbox,
        steps=[
            ValidationStep(name="install", status=install, detail="install detail"),
            ValidationStep(name="build", status=build, detail="build detail"),
            ValidationStep(name="test", status=test, detail="test detail", known_conflict=known),
        ],
        tests_discovered=discovered,
        started_at=T0,
    )


def _scan(status=ScanStatus.COMPLETED, runs=None):
    return ScanRecord(
        id="after",
        repository_name="app",
        repository_root="/w",
        status=status,
        started_at=T0,
        tool_runs=OK_RUNS if runs is None else runs,
    )


def _inputs(validation=None, scan="default", still=(), new=()):
    return VerdictInputs(
        validation=validation or _run(),
        after_scan=_scan() if scan == "default" else scan,
        still_present=list(still),
        resolved=["f1"] if not still else [],
        new_findings=list(new),
    )


LOW = vuln("n1", "x", "1", Severity.LOW)
MED = vuln("n2", "y", "1", Severity.MEDIUM)
HIGH = vuln("n3", "z", "1", Severity.HIGH)
CRIT = vuln("n4", "q", "1", Severity.CRITICAL)
PARTIAL_SCAN = _scan(
    ScanStatus.PARTIAL, [OK_RUNS[0], ToolRunSummary(tool="osv-scanner", status="not_found")]
)

CASES = [
    # (id, inputs, status, confidence, reason fragment)
    ("verified", _inputs(), VerificationStatus.VERIFIED, Confidence.HIGH, "no new HIGH"),
    ("partial scan but scanners ok", _inputs(scan=_scan(ScanStatus.PARTIAL)),
     VerificationStatus.VERIFIED, Confidence.MEDIUM, "tests passed"),
    ("no tests", _inputs(_run(test=N, discovered=0)),
     VerificationStatus.PARTIALLY_VERIFIED, Confidence.MEDIUM, "no tests found"),
    ("no build", _inputs(_run(build=S)),
     VerificationStatus.PARTIALLY_VERIFIED, Confidence.HIGH, "no build step ran"),
    ("new low/medium", _inputs(new=[LOW, MED]),
     VerificationStatus.PARTIALLY_VERIFIED, Confidence.HIGH, "new lower-severity"),
    ("known conflict", _inputs(_run(test=F, known=True)),
     VerificationStatus.PARTIALLY_VERIFIED, Confidence.MEDIUM,
     "fix conflicts with intentional challenge code"),
    ("host unsafe never verified", _inputs(_run("host-unsafe")),
     VerificationStatus.PARTIALLY_VERIFIED, Confidence.MEDIUM, "capped at PARTIALLY_VERIFIED"),
    ("not resolved", _inputs(still=["f1"]),
     VerificationStatus.FAILED, Confidence.HIGH, "still present"),
    ("new high", _inputs(new=[HIGH]), VerificationStatus.FAILED, Confidence.HIGH, "n3 (high)"),
    ("new critical", _inputs(new=[CRIT]), VerificationStatus.FAILED, Confidence.HIGH, "critical"),
    ("build failed", _inputs(_run(build=F, test=S)),
     VerificationStatus.FAILED, Confidence.MEDIUM, "build failed"),
    ("install failed", _inputs(_run(install=F, build=S, test=S)),
     VerificationStatus.FAILED, Confidence.LOW, "dependency install failed"),
    ("tests failed", _inputs(_run(test=F)), VerificationStatus.FAILED, Confidence.MEDIUM,
     "tests failed"),
    ("tests timeout", _inputs(_run(test=T)), VerificationStatus.FAILED, Confidence.MEDIUM,
     "tests timeout"),
    ("no sandbox", _inputs(_run("none", S, S, S)),
     VerificationStatus.UNVERIFIED, Confidence.LOW, "install detail"),
    ("no sandbox, unresolved", _inputs(_run("none", S, S, S), still=["f1"]),
     VerificationStatus.FAILED, Confidence.LOW, "still present"),
    ("validation skipped", _inputs(_run(install=S, build=S, test=S)),
     VerificationStatus.UNVERIFIED, Confidence.LOW, "validation did not run"),
    ("osv missing", _inputs(scan=PARTIAL_SCAN),
     VerificationStatus.UNVERIFIED, Confidence.LOW, "osv-scanner=not_found"),
    ("rescan failed", _inputs(scan=_scan(ScanStatus.FAILED)),
     VerificationStatus.UNVERIFIED, Confidence.LOW, "rescan failed"),
    ("no rescan", _inputs(scan=None), VerificationStatus.UNVERIFIED, Confidence.LOW,
     "rescan did not run"),
]  # fmt: skip


@pytest.mark.parametrize(
    ("inputs", "status", "confidence", "fragment"),
    [c[1:] for c in CASES],
    ids=[c[0] for c in CASES],
)
def test_verdict_table(inputs, status, confidence, fragment):
    got_status, got_confidence, reasons = decide_verdict(inputs)
    assert got_status is status
    assert got_confidence is confidence
    assert any(fragment in r for r in reasons), reasons


def test_host_unsafe_is_never_verified():
    for validation in (_run("host-unsafe"), _run("host-unsafe", test=N, discovered=0)):
        status, *_ = decide_verdict(_inputs(validation))
        assert status is not VerificationStatus.VERIFIED


# --- verify_case on a real database -------------------------------------------------------


@pytest.fixture
def db(tmp_path):
    with Database(tmp_path / "guardian.db") as database:
        yield database


def _applied(case, worktree="/home/worktrees/x"):
    return AppliedChange(
        case_id=case.id,
        branch=f"guardian/fix-{case.id}",
        worktree_path=Path(worktree),
        commit_sha="abc",
        base_commit="def",
        changed_paths=["package.json"],
    )


def _before(db):
    make_scan(
        db,
        "before",
        "/repo",
        findings=[vuln("f1"), vuln("other", "express", "4.0.0", Severity.LOW)],
        sbom=sbom_with("pkg:npm/lodash@4.17.20", "pkg:npm/express@4.0.0"),
    )
    return make_case(db, "/repo")


def test_verify_case_resolved(db):
    case = _before(db)
    scanned: list[Path] = []

    def scan_fn(path):
        scanned.append(path)
        return make_scan(
            db,
            "after",
            str(path),
            findings=[vuln("other", "express", "4.0.0", Severity.LOW)],
            sbom=sbom_with("pkg:npm/lodash@4.17.21", "pkg:npm/express@4.0.0"),
        )

    result = verify_case(db, case, _applied(case), _run(), before_scan_id="before", scan_fn=scan_fn)
    assert scanned == [Path("/home/worktrees/x")]
    assert result.status is VerificationStatus.VERIFIED
    assert result.confidence is Confidence.HIGH
    assert result.target_findings_resolved == ["f1"]
    assert result.findings_still_present == []
    assert result.new_findings == []
    assert result.after_scan_id == "after"
    assert result.risk_before is not None
    assert result.risk_before > 0
    assert result.risk_after == 0.0
    assert [(c.purl_base, c.from_version, c.to_version) for c in result.sbom_diff.changed] == [
        ("pkg:npm/lodash", "4.17.20", "4.17.21")
    ]
    assert db.remediation.verifications(case.id) == [result]
    last = db.audit.list(case.id)[-1]
    assert last.event == "verify:finished"
    assert '"status":"VERIFIED"' in last.payload_json


def test_verify_case_not_resolved_and_new_high(db):
    case = _before(db)

    def scan_fn(path):
        return make_scan(db, "after", str(path), findings=[vuln("f1"), vuln("n3", "z", "1")])

    result = verify_case(db, case, _applied(case), _run(), before_scan_id="before", scan_fn=scan_fn)
    assert result.status is VerificationStatus.FAILED
    assert result.findings_still_present == ["f1"]
    assert result.new_findings == ["n3"]
    assert result.risk_after == result.risk_before


def test_verify_case_scan_error_and_docker_missing(db):
    case = _before(db)

    def boom(path):
        raise RuntimeError("cdxgen exploded")

    result = verify_case(db, case, _applied(case), _run(), before_scan_id="before", scan_fn=boom)
    assert result.status is VerificationStatus.UNVERIFIED
    assert result.after_scan_id is None
    assert result.risk_after is None
    assert "cdxgen exploded" in result.reasons[0]

    def clean(path):
        return make_scan(db, "after2", str(path))

    no_docker = _run("none", S, S, S)
    result = verify_case(
        db, case, _applied(case), no_docker, before_scan_id="before", scan_fn=clean
    )
    assert result.status is VerificationStatus.UNVERIFIED


def test_max_risk_handles_unknown_ids(db):
    _before(db)
    assert max_risk(db, "before", ["missing"]) is None
    assert max_risk(db, "before", ["f1"]) > 0
    assert verify_module._safe_risk(db, "no-such-scan", ["f1"]) is None


def test_default_scan_fn_uses_pipeline(db, monkeypatch):
    seen = {}

    class FakePipeline:
        def __init__(self, database, settings, *, lockfile_generator):
            seen["args"] = (database, settings, lockfile_generator)

        def run(self, path):
            seen["path"] = path
            record = ScanRecord(
                id="s9",
                repository_name="x",
                repository_root=str(path),
                status=ScanStatus.COMPLETED,
                started_at=datetime.now(UTC),
            )
            return type("Outcome", (), {"record": record})()

    import guardian.orchestration.pipeline as pipeline_module

    monkeypatch.setattr(pipeline_module, "ScanPipeline", FakePipeline)

    def generator(root, out):
        return None, None

    scan = default_scan_fn(db, None, lockfile_generator=generator)
    assert scan(Path("/wt")) == "s9"
    assert seen["args"] == (db, None, generator)
    assert seen["path"] == Path("/wt")


# --- run_remediation (CLI fallback) -------------------------------------------------------


@pytest.fixture
def flow(tmp_path, db):
    repo = tmp_path / "repo"
    head = init_repo(
        repo, {"package.json": '{"dependencies": {"lodash": "4.17.20"}, "scripts": {}}\n'}
    )
    make_scan(
        db,
        "before",
        str(repo),
        head=head,
        findings=[vuln("f1")],
        sbom=sbom_with("pkg:npm/lodash@4.17.20"),
    )
    case = make_case(db, str(repo))
    save_plan(db, case, [make_candidate(case)])
    db.remediation.update_status(case.id, CaseStatus.AWAITING_DECISION)
    case = db.remediation.update_status(case.id, CaseStatus.APPROVED)

    def scan_fn(path):
        return make_scan(db, "after", str(path), sbom=sbom_with("pkg:npm/lodash@4.17.21"))

    return {
        "db": db,
        "repo": repo,
        "case": case,
        "home": tmp_path / "home",
        "scan_fn": scan_fn,
        "runner": ToolRunner(ExecutionPolicy(allowed_tools=frozenset({"git"}))),
    }


def _remediate(flow, sandbox, apply_fn=bump_lodash):
    return run_remediation(
        flow["db"],
        flow["case"],
        decision(flow["case"]),
        repo_root=flow["repo"],
        guardian_home=flow["home"],
        runner=flow["runner"],
        sandbox=sandbox,
        scan_fn=flow["scan_fn"],
        apply_fn=apply_fn,
    )


def _statuses(db, case_id):
    return [e.event for e in db.audit.list(case_id) if e.event.startswith("status:")]


def _with_build_and_tests(flow):
    pkg = flow["repo"] / "package.json"
    pkg.write_text(
        '{"dependencies": {"lodash": "4.17.20"}, '
        '"scripts": {"build:server": "tsc", "test:server": "node --test"}}\n'
    )
    git(flow["repo"], "commit", "-q", "-am", "scripts")
    head = git(flow["repo"], "rev-parse", "HEAD")
    flow["db"].conn.execute("UPDATE scans SET git_commit = ? WHERE id = 'before'", (head,))
    flow["db"].conn.commit()


def test_run_remediation_verified(flow):
    _with_build_and_tests(flow)
    sandbox = FakeSandbox(
        results={"test": StepResult(StepStatus.PASSED, 0, 1, "ℹ tests 4\nℹ pass 4\nℹ fail 0\n")}
    )
    run = _remediate(flow, sandbox)
    assert run.verification.status is VerificationStatus.VERIFIED
    assert run.case.status is CaseStatus.VERIFIED
    assert _statuses(flow["db"], run.case.id)[-3:] == [
        "status:APPROVED->APPLYING",
        "status:APPLYING->VALIDATING",
        "status:VALIDATING->VERIFIED",
    ]
    assert Path(run.validation.steps[0].log_path).is_relative_to(flow["home"] / "logs")


def test_run_remediation_partial_goes_back_to_review(flow):
    run = _remediate(flow, FakeSandbox())  # no build:server / test scripts
    assert run.verification.status is VerificationStatus.PARTIALLY_VERIFIED
    assert run.case.status is CaseStatus.VALIDATION_FAILED


def test_run_remediation_without_docker_is_unverified(flow):
    run = _remediate(flow, FakeSandbox(available=(False, "docker daemon not reachable")))
    assert run.validation.sandbox == "none"
    assert run.verification.status is VerificationStatus.UNVERIFIED
    assert run.case.status is CaseStatus.VALIDATION_FAILED


def test_run_remediation_apply_failure(flow):
    run = _remediate(flow, FakeSandbox(), apply_fn=lambda wt, c: [])
    assert run.case.status is CaseStatus.VALIDATION_FAILED
    assert run.applied is None
    assert "changed no files" in run.errors[0]
    assert _statuses(flow["db"], run.case.id)[-1] == "status:APPLYING->VALIDATION_FAILED"


def _change(finding_id, commit):
    from guardian.core.models import ChangeCategory, ChangeDetails, Finding, FindingKind

    return Finding(
        id=finding_id,
        kind=FindingKind.CHANGE,
        title="Dependency manifest changed",
        severity=Severity.INFO,
        tool="git",
        details=ChangeDetails(
            category=ChangeCategory.MANIFEST, commit=commit, paths=["package.json"]
        ),
    )


def test_own_fix_commit_is_not_a_new_finding(db):
    """The rescan's git history reports Guardian's own fix commit; that is the fix itself."""
    case = _before(db)

    def scan_fn(path):
        return make_scan(
            db,
            "after",
            str(path),
            findings=[_change("own", "abc"), _change("someone-else", "f" * 40)],
            sbom=sbom_with("pkg:npm/lodash@4.17.21"),
        )

    result = verify_case(db, case, _applied(case), _run(), before_scan_id="before", scan_fn=scan_fn)
    assert result.new_findings == ["someone-else"]  # someone else's change still counts
    assert result.status is VerificationStatus.PARTIALLY_VERIFIED

    def only_own(path):
        return make_scan(
            db,
            "after2",
            str(path),
            findings=[_change("own2", "abc")],
            sbom=sbom_with("pkg:npm/lodash@4.17.21"),
        )

    result = verify_case(
        db, case, _applied(case), _run(), before_scan_id="before", scan_fn=only_own
    )
    assert result.new_findings == []
    assert result.status is VerificationStatus.VERIFIED

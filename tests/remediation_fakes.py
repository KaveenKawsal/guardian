"""Shared fakes and builders for the Milestone 5 (apply/validate/verify) tests."""

import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from guardian.core.models import (
    Component,
    Ecosystem,
    Finding,
    FindingKind,
    GitInfo,
    Priority,
    RepositoryProfile,
    Sbom,
    ScanStatus,
    Severity,
    ToolRunSummary,
    VulnerabilityDetails,
)
from guardian.core.remediation_models import (
    DecisionType,
    HumanDecision,
    ModifyPayload,
    RemediationActionType,
    RemediationCandidate,
    RemediationCase,
    RemediationPlan,
    SemverJump,
    StepStatus,
    candidate_id_for,
    case_id_for,
    fingerprint_for,
)
from guardian.execution.results import ToolResult, ToolStatus
from guardian.remediation.sandbox import SandboxConfig, StepResult

T0 = datetime(2026, 1, 1, tzinfo=UTC)

Handler = Callable[[str, list[str], Path], ToolResult]


def ok(tool: str, args: list[str], stdout: str = "", exit_code: int = 0) -> ToolResult:
    status = ToolStatus.SUCCESS if exit_code == 0 else ToolStatus.FAILED
    return ToolResult(tool=tool, args=args, status=status, exit_code=exit_code, stdout=stdout)


class FakeRunner:
    """Duck-typed ToolRunner that records calls and answers through ``handler``."""

    def __init__(self, handler: Handler | None = None, available: frozenset[str] | None = None):
        self.handler = handler
        self.available = available
        self.calls: list[tuple[str, list[str], Path, float | None]] = []

    def is_available(self, tool: str) -> bool:
        return self.available is None or tool in self.available

    def run(self, tool, args, *, cwd, timeout_seconds=None, env=None):
        args = list(args)
        self.calls.append((tool, args, Path(cwd), timeout_seconds))
        if self.handler is None:
            return ok(tool, args)
        return self.handler(tool, args, Path(cwd))


class FakeSandbox:
    """Duck-typed Sandbox. ``results`` keys: lockfile, install, build, test."""

    def __init__(
        self,
        *,
        kind: str = "docker",
        available: tuple[bool, str] = (True, "docker 27.0"),
        results: dict[str, StepResult] | None = None,
        lockfile: bytes | None = b'{"lockfileVersion": 3}',
        config: SandboxConfig | None = None,
    ):
        self.kind = kind
        self._available = available
        self.results = results or {}
        self.lockfile = lockfile
        self.config = config or SandboxConfig()
        self.runs: list[dict] = []
        self.installs: list[dict] = []

    def available(self):
        return self._available

    def run(self, image, workdir_copy, command, *, network, timeout, name):
        command = list(command)
        self.runs.append(
            {
                "image": image,
                "workdir": workdir_copy,
                "files": sorted(p.name for p in workdir_copy.iterdir()),
                "command": command,
                "network": network,
                "timeout": timeout,
                "name": name,
            }
        )
        if command[:2] == ["npm", "install"]:
            if self.lockfile is not None:
                (workdir_copy / "package-lock.json").write_bytes(self.lockfile)
            return self.results.get("lockfile", StepResult(StepStatus.PASSED, 0, argv=("npm",)))
        key = "build" if "build:server" in command else "test"
        return self.results.get(key, StepResult(StepStatus.PASSED, 0))

    def install_dependencies(self, deps_dir, work_copy, *, name):
        self.installs.append(
            {
                "deps": sorted(p.name for p in deps_dir.iterdir()),
                "copy": sorted(p.name for p in work_copy.iterdir()),
                "name": name,
            }
        )
        result = self.results.get("install", StepResult(StepStatus.PASSED, 0, detail="built"))
        image = "guardian-deps:0123456789ab" if result.status is StepStatus.PASSED else None
        return image, result


# --- git ---------------------------------------------------------------------------------


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def init_repo(root: Path, files: dict[str, str]) -> str:
    root.mkdir(parents=True, exist_ok=True)
    for rel, content in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    git(root, "init", "-q", "-b", "main")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "initial")
    return git(root, "rev-parse", "HEAD")


# --- storage builders --------------------------------------------------------------------


def profile_for(root: str, head: str | None = None) -> RepositoryProfile:
    return RepositoryProfile(
        name="app",
        root=root,
        profiled_at=T0,
        total_files=1,
        total_bytes=1,
        git=GitInfo(is_repository=True, branch="main", head_commit=head),
    )


def vuln(
    finding_id: str, package: str = "lodash", version: str = "4.17.20", severity=Severity.HIGH
):
    return Finding(
        id=finding_id,
        kind=FindingKind.VULNERABILITY,
        title=f"{finding_id} in {package}",
        severity=severity,
        tool="osv-scanner",
        details=VulnerabilityDetails(
            vulnerability_id=f"GHSA-{finding_id}",
            package=package,
            version=version,
            ecosystem="npm",
            purl=f"pkg:npm/{package}@{version}",
            cvss_score=7.5,
        ),
    )


def sbom_with(*purls: str) -> Sbom:
    components = []
    for purl in purls:
        name, _, version = purl.removeprefix("pkg:npm/").partition("@")
        components.append(
            Component(
                ref=purl,
                name=name,
                version=version,
                purl=purl,
                purl_type="npm",
                ecosystem=Ecosystem.NODE,
            )
        )
    return Sbom(spec_version="1.5", generator="test", components=components)


DEFAULT_TOOL_RUNS = (
    ToolRunSummary(tool="cdxgen", status="success"),
    ToolRunSummary(tool="osv-scanner", status="success"),
)


def make_scan(
    db,
    scan_id: str,
    root: str,
    *,
    findings=(),
    sbom: Sbom | None = None,
    head: str | None = None,
    status: ScanStatus = ScanStatus.COMPLETED,
    tool_runs=DEFAULT_TOOL_RUNS,
) -> str:
    repo_id = db.repositories.upsert(root, "app")
    db.scans.create(scan_id, repo_id, T0, profile_for(root, head))
    if sbom is not None:
        db.sboms.save(scan_id, sbom)
    db.findings.save(scan_id, list(findings), [])
    db.scans.finish(
        scan_id,
        status=status,
        finished_at=T0,
        tool_runs=list(tool_runs),
        warnings=[],
        component_count=len(sbom.components) if sbom else 0,
        finding_count=len(findings),
    )
    return scan_id


def make_case(db, root: str, scan_id: str = "before", finding_ids=("f1",)) -> RemediationCase:
    fp = fingerprint_for(root, "pkg:npm/lodash@4.17.20", "GHSA-f1")
    case = RemediationCase(
        id=case_id_for(fp),
        fingerprint=fp,
        scan_id=scan_id,
        repository_root=root,
        finding_ids=list(finding_ids),
        title="lodash prototype pollution",
        priority=Priority.P2,
        created_at=T0,
        updated_at=T0,
    )
    return db.remediation.create(case)


def make_candidate(case: RemediationCase, to_version: str = "4.17.21", action=None):
    action = action or RemediationActionType.UPGRADE
    return RemediationCandidate(
        id=candidate_id_for(case.fingerprint, action, "pkg:npm/lodash", to_version),
        case_id=case.id,
        finding_ids=list(case.finding_ids),
        action_type=action,
        component="pkg:npm/lodash",
        from_version="4.17.20",
        to_version=to_version,
        manifest_path="package.json",
        fixes_finding_ids=list(case.finding_ids),
        semver_jump=SemverJump.PATCH,
        rollback="git revert HEAD",
        version_verified=True,
    )


def save_plan(db, case: RemediationCase, candidates: list[RemediationCandidate]) -> None:
    db.remediation.save_candidates(case.id, candidates)
    db.remediation.save_plan(
        RemediationPlan(
            case_id=case.id,
            chosen_candidate_id=candidates[0].id,
            alternatives=[c.id for c in candidates[1:]],
            rationale="lowest jump",
            confidence="high",
            source="verified",
            decided_by="deterministic",
        )
    )


def decision(case: RemediationCase, kind=DecisionType.ACCEPT, **kwargs) -> HumanDecision:
    modify = kwargs.pop("modify", None)
    return HumanDecision(
        case_id=case.id,
        decision=kind,
        modify=ModifyPayload(**modify) if modify else None,
        actor_id="acc-1",
        actor_display="Alice Approver",
        channel="jira",
        decided_at=T0,
        **kwargs,
    )


def bump_lodash(worktree: Path, candidate: RemediationCandidate) -> list[str]:
    """Fake adapter apply_candidate: rewrite the lodash version in package.json."""
    path = worktree / "package.json"
    text = path.read_text(encoding="utf-8")
    path.write_text(
        text.replace(candidate.from_version or "", candidate.to_version or ""), encoding="utf-8"
    )
    return ["package.json"]


# --- remediation graph services ---------------------------------------------------------


class StubServices:
    """Duck-typed ``RemediationServices`` for runtime/CLI tests: no git, Docker or rescan.

    ``verify_statuses`` is consumed one per verify call (the last one repeats).
    """

    def __init__(self, verify_statuses=("VERIFIED",), apply_errors=()):
        self.calls: list[tuple] = []
        self.verify_statuses = list(verify_statuses)
        self.apply_errors = list(apply_errors)

    def plan(self, case_id):
        self.calls.append(("plan", case_id))

    def publish(self, case_id):
        self.calls.append(("publish", case_id))

    def notify(self, case_id, stage, payload):
        self.calls.append(("notify", stage, payload["attempt"]))

    def apply(self, case_id, decision):
        self.calls.append(("apply", decision.decision))
        if self.apply_errors:
            raise self.apply_errors.pop(0)
        return {"case_id": case_id, "branch": f"guardian/fix-{case_id}"}

    def validate(self, case_id, applied):
        self.calls.append(("validate", case_id))
        return {"case_id": case_id, "sandbox": "docker", "steps": []}

    def verify(self, case_id, applied, validation):
        status = (
            self.verify_statuses.pop(0)
            if len(self.verify_statuses) > 1
            else self.verify_statuses[0]
        )
        self.calls.append(("verify", status))
        return {"case_id": case_id, "status": status, "reasons": [f"rescan {status}"]}

    def record_acceptance(self, case_id, decision):
        self.calls.append(("record_acceptance", decision.decline_reason))


def stub_runtime(monkeypatch, services=None):
    """Make every runtime use ``services`` (a ``StubServices`` by default)."""
    from guardian.remediation import runtime

    services = services or StubServices()
    monkeypatch.setattr(runtime, "build_services", lambda db, settings, **kwargs: services)
    return services

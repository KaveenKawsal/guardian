"""Apply an approved remediation in an isolated git worktree (rule 8).

    git worktree add <guardian_home>/worktrees/<case_id> -b guardian/fix-<case_id> <base>

Guardian only ever works inside its own worktree on a ``guardian/fix-*`` branch: it never
touches the user's working tree, never checks out the default branch and never pushes. Every
git call goes through ``ToolRunner``, which prepends ``GIT_HARDENING_ARGS`` (no hooks, no
fsmonitor, no external diff, no network protocols). The commit adds
``-c user.name=Guardian -c user.email=guardian@localhost -c commit.gpgsign=false`` so it never
depends on repository or user configuration.

Which change is applied follows the human decision:

* ACCEPT -> ``decision.candidate_id`` if given, else the candidate passed in, else the plan's;
* MODIFY candidate_id -> that stored candidate;
* MODIFY version=X -> the base candidate with ``to_version=X`` (a new deterministic id);
* MODIFY action=A [target=T] -> a stored candidate with that action (and component), else the
  base candidate with the action replaced (the adapter rejects non-code actions);
* MODIFY branch=/commit= -> the worktree starts at that ref (verified with
  ``git rev-parse --verify <ref>^{commit}``) and no edit or commit is made.
"""

import importlib
import re
import shutil
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from guardian.core.exceptions import GuardianError
from guardian.core.remediation_models import (
    DecisionType,
    HumanDecision,
    RemediationCandidate,
    RemediationCase,
    SemverJump,
    candidate_id_for,
)
from guardian.execution.results import ToolResult
from guardian.execution.runner import ToolRunner
from guardian.storage.database import Database
from guardian.storage.remediation import SYSTEM_ACTOR

GIT = "git"
BRANCH_PREFIX = "guardian/fix-"
COMMIT_IDENTITY: tuple[str, ...] = (
    "-c",
    "user.name=Guardian",
    "-c",
    "user.email=guardian@localhost",
    "-c",
    "commit.gpgsign=false",
)
_CASE_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_COMMIT_SHA = re.compile(r"^[0-9a-fA-F]{7,64}$")
_GIT_TIMEOUT = 300

ApplyFn = Callable[[Path, RemediationCandidate], list[str]]
"""``apply_fn(worktree, candidate) -> changed repository-relative paths``."""


class RemediationApplyError(GuardianError):
    """The approved change could not be applied in the worktree."""


@dataclass(frozen=True)
class AppliedChange:
    case_id: str
    branch: str
    worktree_path: Path
    commit_sha: str
    base_commit: str
    changed_paths: list[str] = field(default_factory=list)
    candidate_id: str | None = None
    manual_ref: str | None = None
    """The human-provided branch/commit when the change was made by a human."""


def branch_for(case_id: str) -> str:
    return f"{BRANCH_PREFIX}{case_id}"


def worktree_path_for(guardian_home: Path, case_id: str) -> Path:
    """``<guardian_home>/worktrees/<case_id>``; refuses ids that could escape that directory."""
    if not _CASE_ID.fullmatch(case_id):
        msg = f"Refusing unsafe case id {case_id!r}"
        raise RemediationApplyError(msg)
    root = (guardian_home / "worktrees").resolve()
    path = (root / case_id).resolve()
    _assert_under(path, root)
    return path


def _assert_under(path: Path, root: Path) -> None:
    if path == root or not path.is_relative_to(root):
        msg = f"Refusing to touch {path}: not inside {root}"
        raise RemediationApplyError(msg)


def _assert_guardian_branch(branch: str) -> None:
    if not branch.startswith(BRANCH_PREFIX) or len(branch) == len(BRANCH_PREFIX):
        msg = f"Refusing to touch branch {branch!r}: not a {BRANCH_PREFIX}* branch"
        raise RemediationApplyError(msg)


def _one_line(text: str | None) -> str:
    return " ".join((text or "").split())[:200]


class _Git:
    def __init__(self, runner: ToolRunner) -> None:
        self.runner = runner

    def run(self, cwd: Path, *args: str) -> ToolResult:
        return self.runner.run(GIT, list(args), cwd=cwd, timeout_seconds=_GIT_TIMEOUT)

    def check(self, cwd: Path, *args: str) -> str:
        result = self.run(cwd, *args)
        if not result.ok:
            detail = (result.stderr or result.error or "").strip()
            msg = f"git {args[0]} failed: {detail[:500]}"
            raise RemediationApplyError(msg)
        return result.stdout.strip()


# --- candidate selection ----------------------------------------------------------------


def _plan_candidate(db: Database, case: RemediationCase) -> RemediationCandidate | None:
    plan = db.remediation.plan(case.id)
    if plan is None:
        return None
    return _stored(db, case, plan.chosen_candidate_id)


def _stored(db: Database, case: RemediationCase, candidate_id: str) -> RemediationCandidate:
    for candidate in db.remediation.candidates(case.id):
        if candidate.id == candidate_id:
            return candidate
    msg = f"Case {case.id} has no candidate {candidate_id!r}"
    raise RemediationApplyError(msg)


def resolve_candidate(
    db: Database,
    case: RemediationCase,
    candidate: RemediationCandidate | None,
    decision: HumanDecision,
) -> RemediationCandidate:
    """The candidate a human decision asks Guardian to apply (see module docstring)."""
    if decision.decision is DecisionType.DECLINE:
        msg = f"Case {case.id} was declined; nothing to apply"
        raise RemediationApplyError(msg)
    if decision.decision is DecisionType.ACCEPT and decision.candidate_id:
        return _stored(db, case, decision.candidate_id)
    modify = decision.modify
    if modify is not None and modify.candidate_id is not None:
        return _stored(db, case, modify.candidate_id)

    base = candidate or _plan_candidate(db, case)
    if modify is not None and modify.action is not None:
        for stored in db.remediation.candidates(case.id):
            if stored.action_type is modify.action and modify.target in {None, stored.component}:
                return stored
    if base is None:
        msg = f"Case {case.id} has no planned candidate to apply"
        raise RemediationApplyError(msg)
    if modify is not None and modify.version is not None:
        return base.model_copy(
            update={
                "id": candidate_id_for(
                    case.fingerprint, base.action_type, base.component, modify.version
                ),
                "to_version": modify.version,
                "semver_jump": SemverJump.UNKNOWN,
                "version_verified": None,
                "compatibility_notes": [],
                "evidence": [*base.evidence, f"version {modify.version} requested by a human"],
            }
        )
    if modify is not None and modify.action is not None:
        component = modify.target or base.component
        return base.model_copy(
            update={
                "id": candidate_id_for(case.fingerprint, modify.action, component, base.to_version),
                "action_type": modify.action,
                "component": component,
            }
        )
    return base


def _default_apply_fn() -> ApplyFn:
    module = importlib.import_module("guardian.adapters.node")
    apply_fn = getattr(module, "apply_candidate", None)
    if apply_fn is None:
        msg = "The node adapter has no apply_candidate(); cannot apply the fix"
        raise RemediationApplyError(msg)
    return apply_fn


# --- worktree management ----------------------------------------------------------------


def _remove_previous(git: _Git, repo_root: Path, worktree: Path, branch: str) -> None:
    """Remove a worktree/branch left by an earlier attempt (only Guardian's own)."""
    _assert_guardian_branch(branch)
    # Fails harmlessly when nothing is registered at that path.
    git.run(repo_root, "worktree", "remove", "--force", str(worktree))
    if worktree.is_symlink():
        worktree.unlink()
    elif worktree.exists():
        shutil.rmtree(worktree)
    git.run(repo_root, "worktree", "prune")
    exists = git.run(repo_root, "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}")
    if exists.ok:
        git.check(repo_root, "branch", "-D", branch)


def _verify_ref(git: _Git, repo_root: Path, ref: str, *, commit: bool) -> str:
    """Resolve a human-provided branch/commit to a commit sha, rejecting option-like input."""
    if ref.startswith("-") or any(c.isspace() for c in ref):
        msg = f"Refusing suspicious ref {ref!r}"
        raise RemediationApplyError(msg)
    if commit and not _COMMIT_SHA.fullmatch(ref):
        msg = f"commit= must be a hexadecimal sha, got {ref!r}"
        raise RemediationApplyError(msg)
    if not commit:
        git.check(repo_root, "check-ref-format", "--branch", ref)
    return git.check(repo_root, "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}")


def _safe_paths(worktree: Path, paths: Sequence[str]) -> list[str]:
    clean: list[str] = []
    for raw in paths:
        rel = PurePosixPath(raw)
        if rel.is_absolute() or ".." in rel.parts or not rel.parts:
            msg = f"apply_fn returned an unsafe path {raw!r}"
            raise RemediationApplyError(msg)
        _assert_under((worktree / rel).resolve(), worktree)
        clean.append(rel.as_posix())
    return sorted(set(clean))


def commit_message(
    case: RemediationCase,
    candidate: RemediationCandidate,
    decision: HumanDecision,
    jira_key: str | None,
) -> str:
    target = f" -> {candidate.to_version}" if candidate.to_version else ""
    lines = [
        f"guardian: {candidate.action_type.value.lower()} {candidate.component}{target}",
        "",
        f"Guardian-Case: {case.id}",
        f"Guardian-Findings: {', '.join(case.finding_ids) or '-'}",
        f"Guardian-Candidate: {candidate.id}",
        (
            f"Approved-By: {_one_line(decision.actor_display)} "
            f"({_one_line(decision.actor_id)}) via {decision.channel}"
        ),
        f"Decision: {decision.decision.value}",
    ]
    if jira_key:
        lines.append(f"Jira: {_one_line(jira_key)}")
    lines.append(f"Rollback: {_one_line(candidate.rollback)}")
    return "\n".join(lines) + "\n"


def _jira_key(db: Database, case: RemediationCase) -> str | None:
    if case.jira_key:
        return case.jira_key
    link = db.remediation.jira_link(case.id)
    return link.issue_key if link else None


def _base_commit(db: Database, git: _Git, case: RemediationCase, repo_root: Path) -> str:
    scanned = db.scans.get(case.scan_id).git_commit
    ref = scanned or "HEAD"
    return git.check(repo_root, "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}")


def apply_case(  # noqa: PLR0913 - every collaborator is injectable for tests
    db: Database,
    case: RemediationCase,
    candidate: RemediationCandidate | None,
    decision: HumanDecision,
    *,
    repo_root: Path,
    guardian_home: Path,
    runner: ToolRunner,
    apply_fn: ApplyFn | None = None,
    actor: str = SYSTEM_ACTOR,
) -> AppliedChange:
    """Create ``guardian/fix-<case_id>`` in its own worktree, apply and commit the change."""
    git = _Git(runner)
    repo_root = repo_root.resolve()
    worktree = worktree_path_for(guardian_home, case.id)
    branch = branch_for(case.id)
    _assert_guardian_branch(branch)
    modify = decision.modify
    manual_ref = None if modify is None else (modify.branch or modify.commit)
    db.audit.append(
        case.id,
        "apply:started",
        actor,
        {"branch": branch, "worktree": str(worktree), "decision": decision.decision.value},
    )
    try:
        chosen = None if manual_ref else resolve_candidate(db, case, candidate, decision)
        if manual_ref and modify is not None:
            base = _verify_ref(git, repo_root, manual_ref, commit=modify.commit is not None)
        else:
            base = _base_commit(db, git, case, repo_root)
        _remove_previous(git, repo_root, worktree, branch)
        worktree.parent.mkdir(parents=True, exist_ok=True)
        git.check(repo_root, "worktree", "add", "-b", branch, str(worktree), base)
        if chosen is None:
            scanned = _base_commit(db, git, case, repo_root)
            diff = git.check(worktree, "diff", "--name-only", scanned, base, "--")
            applied = AppliedChange(
                case_id=case.id,
                branch=branch,
                worktree_path=worktree,
                commit_sha=base,
                base_commit=scanned,
                changed_paths=[p for p in diff.splitlines() if p],
                manual_ref=manual_ref,
            )
        else:
            applied = _edit_and_commit(
                git, db, case, chosen, decision, worktree, branch, base, apply_fn
            )
    except GuardianError as exc:
        db.audit.append(case.id, "apply:failed", actor, {"branch": branch, "error": str(exc)})
        raise
    db.audit.append(
        case.id,
        "apply:committed",
        actor,
        {
            "branch": applied.branch,
            "commit": applied.commit_sha,
            "base": applied.base_commit,
            "changed_paths": applied.changed_paths,
            "candidate_id": applied.candidate_id,
            "manual_ref": applied.manual_ref,
        },
    )
    return applied


def _edit_and_commit(  # noqa: PLR0913, PLR0917 - internal helper of apply_case
    git: _Git,
    db: Database,
    case: RemediationCase,
    candidate: RemediationCandidate,
    decision: HumanDecision,
    worktree: Path,
    branch: str,
    base: str,
    apply_fn: ApplyFn | None,
) -> AppliedChange:
    fn = apply_fn or _default_apply_fn()
    changed = _safe_paths(worktree, fn(worktree, candidate))
    if not changed:
        msg = f"Candidate {candidate.id} changed no files"
        raise RemediationApplyError(msg)
    git.check(worktree, "add", "--", *changed)
    message = commit_message(case, candidate, decision, _jira_key(db, case))
    git.check(worktree, *COMMIT_IDENTITY, "commit", "--no-verify", "--quiet", "-m", message)
    sha = git.check(worktree, "rev-parse", "HEAD")
    return AppliedChange(
        case_id=case.id,
        branch=branch,
        worktree_path=worktree,
        commit_sha=sha,
        base_commit=base,
        changed_paths=changed,
        candidate_id=candidate.id,
    )

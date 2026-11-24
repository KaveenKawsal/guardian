"""Do independently verified fixes still work together?

Each accepted case is fixed, built, tested and rescanned on its own ``guardian/fix-<case>``
branch, so fixes run in parallel without seeing each other. Before they are combined, Guardian
checks every pair of fix branches in the same repository:

* ``git merge-tree --write-tree`` merges the two branches in memory (no worktree, no checkout,
  nothing written to the user's working tree) and lists conflicting files;
* two fixes that change the same package to different versions are flagged even when git
  merges them cleanly, since only one version can win.

The result is advisory: it never changes a case's status or verdict.
"""

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from guardian.execution.runner import ToolRunner
from guardian.remediation.apply import branch_for
from guardian.storage.database import Database

_GIT_TIMEOUT = 60
Status = Literal["compatible", "conflict", "same_package", "unknown"]


@dataclass(frozen=True, slots=True)
class PairCheck:
    case_id: str
    title: str
    status: Status
    detail: str
    files: tuple[str, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return asdict(self) | {"files": list(self.files)}


def _branch_exists(runner: ToolRunner, repo: Path, branch: str) -> bool:
    result = runner.run(
        "git",
        ["rev-parse", "--verify", "--quiet", f"refs/heads/{branch}"],
        cwd=repo,
        timeout_seconds=_GIT_TIMEOUT,
    )
    return result.ok


def _targets(db: Database, case_id: str) -> dict[str, str | None]:
    """``component -> to_version`` of the fix that was applied (the latest apply event)."""
    for event in reversed(db.audit.list(case_id)):
        if event.event == "apply:committed":
            payload = json.loads(event.payload_json or "{}")
            candidate_id = payload.get("candidate_id") if isinstance(payload, dict) else None
            for candidate in db.remediation.candidates(case_id):
                if candidate.id == candidate_id:
                    return {candidate.component: candidate.to_version}
    return {}


def merge_check(runner: ToolRunner, repo: Path, ours: str, theirs: str) -> tuple[Status, list[str]]:
    """Merge two branches in memory. Exit 0 = clean, 1 = conflicts (files listed)."""
    result = runner.run(
        "git",
        ["merge-tree", "--write-tree", "--name-only", "--no-messages", ours, theirs],
        cwd=repo,
        timeout_seconds=_GIT_TIMEOUT,
    )
    if result.exit_code == 0:
        return "compatible", []
    if result.exit_code == 1:
        lines = [line for line in result.stdout.splitlines()[1:] if line.strip()]
        return "conflict", lines
    return "unknown", []


def fix_compatibility(db: Database, case_id: str, runner: ToolRunner) -> list[PairCheck]:
    """Checks of this case's fix branch against every other fix branch in its repository."""
    case = db.remediation.get(case_id)
    repo = Path(case.repository_root)
    ours = branch_for(case.id)
    if not repo.is_dir() or not _branch_exists(runner, repo, ours):
        return []
    mine = _targets(db, case.id)
    checks: list[PairCheck] = []
    for other in db.remediation.list():
        if other.id == case.id or other.repository_root != case.repository_root:
            continue
        theirs = branch_for(other.id)
        if not _branch_exists(runner, repo, theirs):
            continue
        status, files = merge_check(runner, repo, ours, theirs)
        detail = {
            "compatible": "merges cleanly with this fix",
            "conflict": "both fixes edit the same lines; combine them by hand",
            "unknown": "could not compare the branches",
        }.get(status, "")
        if status == "compatible":
            theirs_targets = _targets(db, other.id)
            clash = sorted(
                f"{name} {mine[name]} vs {theirs_targets[name]}"
                for name in mine.keys() & theirs_targets.keys()
                if mine[name] != theirs_targets[name]
            )
            if clash:
                status, detail = "same_package", "both fixes pin " + "; ".join(clash)
        checks.append(PairCheck(other.id, other.title, status, detail, tuple(files)))
    return checks

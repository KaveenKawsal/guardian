"""Cross-case fix compatibility: real git branches merged in memory."""

import pytest
from remediation_fakes import T0, decision, git, init_repo, make_candidate, make_scan, save_plan

from guardian.core.models import Priority
from guardian.core.remediation_models import RemediationCase
from guardian.execution.policies import ExecutionPolicy
from guardian.execution.runner import ToolRunner
from guardian.remediation.apply import apply_case
from guardian.remediation.cases import case_id_for, fingerprint_for
from guardian.remediation.compatibility import fix_compatibility
from guardian.storage.database import Database

# Far-apart lines so independent edits merge cleanly.
PACKAGE_JSON = (
    '{\n  "name": "app",\n  "dependencies": {\n    "lodash": "4.17.20",\n'
    + "".join(f'    "pad{i}": "1.0.0",\n' for i in range(6))
    + '    "express": "4.17.0"\n  }\n}\n'
)


def _case(db, root, title, purl):
    fp = fingerprint_for(root, purl, f"GHSA-{title}")
    return db.remediation.create(
        RemediationCase(
            id=case_id_for(fp),
            fingerprint=fp,
            scan_id="before",
            repository_root=root,
            finding_ids=["f1"],
            title=title,
            priority=Priority.P2,
            created_at=T0,
            updated_at=T0,
        )
    )


def _replace(old, new):
    def apply_fn(worktree, _candidate):
        path = worktree / "package.json"
        path.write_text(path.read_text().replace(old, new))
        return ["package.json"]

    return apply_fn


@pytest.fixture
def env(tmp_path):
    repo = tmp_path / "repo"
    head = init_repo(repo, {"package.json": PACKAGE_JSON})
    runner = ToolRunner(ExecutionPolicy(allowed_tools=frozenset({"git"})))
    with Database(tmp_path / "guardian.db") as db:
        make_scan(db, "before", str(repo), head=head)
        yield db, repo, tmp_path / "home", runner


def _fix(env, title, purl, old, new, to_version):
    db, repo, home, runner = env
    case = _case(db, str(repo), title, purl)
    candidate = make_candidate(case, to_version).model_copy(update={"component": "pkg:npm/lodash"})
    save_plan(db, case, [candidate])
    apply_case(
        db,
        case,
        None,
        decision(case),
        repo_root=repo,
        guardian_home=home,
        runner=runner,
        apply_fn=_replace(old, new),
    )
    return case


def test_independent_fixes_are_compatible(env):
    db, _, _, runner = env
    a = _fix(
        env,
        "lodash",
        "pkg:npm/lodash@4.17.20",
        '"lodash": "4.17.20"',
        '"lodash": "4.17.21"',
        "4.17.21",
    )
    b = _fix(
        env,
        "express",
        "pkg:npm/express@4.17.0",
        '"express": "4.17.0"',
        '"express": "4.21.2"',
        "4.17.21",
    )
    [check] = fix_compatibility(db, a.id, runner)
    assert check.case_id == b.id
    assert check.status == "compatible"


def test_overlapping_fixes_conflict(env):
    db, _, _, runner = env
    a = _fix(
        env,
        "lodash-a",
        "pkg:npm/lodash@4.17.20",
        '"lodash": "4.17.20"',
        '"lodash": "4.17.21"',
        "4.17.21",
    )
    _fix(
        env,
        "lodash-b",
        "pkg:npm/lodash@4.17.20#b",
        '"lodash": "4.17.20"',
        '"lodash": "4.17.23"',
        "4.17.23",
    )
    [check] = fix_compatibility(db, a.id, runner)
    assert check.status == "conflict"
    assert check.files == ("package.json",)
    assert check.to_json()["files"] == ["package.json"]


def test_same_package_different_versions_flagged_even_without_conflict(env):
    db, _, _, runner = env
    # Both pin lodash (recorded candidates), but edit different lines: git merges cleanly.
    a = _fix(
        env, "a", "pkg:npm/lodash@4.17.20", '"lodash": "4.17.20"', '"lodash": "4.17.21"', "4.17.21"
    )
    _fix(
        env, "b", "pkg:npm/express@4.17.0", '"express": "4.17.0"', '"express": "4.21.2"', "4.17.23"
    )
    [check] = fix_compatibility(db, a.id, runner)
    assert check.status == "same_package"
    assert "4.17.21 vs 4.17.23" in check.detail


def test_no_branch_no_checks(env):
    db, repo, _, runner = env
    case = _case(db, str(repo), "unapplied", "pkg:npm/x@1")
    assert fix_compatibility(db, case.id, runner) == []
    assert git(repo, "branch", "--list", "guardian/*") == ""

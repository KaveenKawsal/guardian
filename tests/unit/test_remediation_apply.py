# ruff: noqa: SLF001, EM101, TRY003 - private guards are under test; inline test errors
from pathlib import Path

import pytest
from remediation_fakes import (
    bump_lodash,
    decision,
    git,
    init_repo,
    make_candidate,
    make_case,
    make_scan,
    save_plan,
)

from guardian.core.exceptions import ApplyError
from guardian.core.remediation_models import DecisionType, DeclineReason, RemediationActionType
from guardian.execution.policies import ExecutionPolicy
from guardian.execution.runner import ToolRunner
from guardian.remediation import apply as apply_module
from guardian.remediation.apply import (
    RemediationApplyError,
    apply_case,
    commit_message,
    resolve_candidate,
    worktree_path_for,
)
from guardian.storage.database import Database

PACKAGE_JSON = '{\n  "name": "app",\n  "dependencies": {\n    "lodash": "4.17.20"\n  }\n}\n'


@pytest.fixture
def env(tmp_path):
    repo = tmp_path / "repo"
    head = init_repo(repo, {"package.json": PACKAGE_JSON, "index.js": "require('lodash')\n"})
    (repo / "scratch.txt").write_text("user's uncommitted work\n")  # must survive
    home = tmp_path / "home"
    with Database(tmp_path / "guardian.db") as db:
        make_scan(db, "before", str(repo), head=head)
        case = make_case(db, str(repo))
        candidates = [make_candidate(case), make_candidate(case, "4.17.22")]
        save_plan(db, case, candidates)
        yield {
            "db": db,
            "repo": repo,
            "head": head,
            "home": home,
            "case": case,
            "candidates": candidates,
            "runner": ToolRunner(ExecutionPolicy(allowed_tools=frozenset({"git"}))),
        }


def _apply(env, dec, candidate=None, apply_fn=bump_lodash):
    return apply_case(
        env["db"],
        env["case"],
        candidate,
        dec,
        repo_root=env["repo"],
        guardian_home=env["home"],
        runner=env["runner"],
        apply_fn=apply_fn,
    )


def _user_state(repo: Path) -> tuple[str, str, str]:
    return (
        git(repo, "rev-parse", "HEAD"),
        git(repo, "status", "--porcelain"),
        git(repo, "rev-parse", "--abbrev-ref", "HEAD"),
    )


def test_apply_commits_on_guardian_branch_in_own_worktree(env):
    db, repo, case = env["db"], env["repo"], env["case"]
    db.remediation.link_jira(case.id, "SEC-42")
    before = _user_state(repo)
    applied = _apply(env, decision(case))

    assert applied.branch == f"guardian/fix-{case.id}"
    assert applied.worktree_path == (env["home"] / "worktrees" / case.id).resolve()
    assert applied.changed_paths == ["package.json"]
    assert applied.base_commit == env["head"]
    assert applied.candidate_id == env["candidates"][0].id
    wt = applied.worktree_path
    assert '"lodash": "4.17.21"' in (wt / "package.json").read_text()
    assert git(wt, "rev-parse", "--abbrev-ref", "HEAD") == applied.branch
    assert git(wt, "rev-parse", "HEAD") == applied.commit_sha
    assert git(wt, "rev-parse", "HEAD~1") == env["head"]
    assert git(wt, "log", "-1", "--format=%an <%ae>") == "Guardian <guardian@localhost>"
    message = git(wt, "log", "-1", "--format=%B")
    assert f"Guardian-Case: {case.id}" in message
    assert "Guardian-Findings: f1" in message
    assert "Approved-By: Alice Approver (acc-1) via jira" in message
    assert "Jira: SEC-42" in message

    # The user's checkout is untouched: same HEAD, same branch, same dirty state.
    assert _user_state(repo) == before
    assert '"lodash": "4.17.20"' in (repo / "package.json").read_text()
    events = [e.event for e in db.audit.list(case.id)]
    assert events[-2:] == ["apply:started", "apply:committed"]


def test_reapply_is_idempotent(env):
    first = _apply(env, decision(env["case"]))
    (first.worktree_path / "stray.txt").write_text("left over")
    second = _apply(env, decision(env["case"], candidate_id=env["candidates"][1].id))
    assert second.worktree_path == first.worktree_path
    assert not (second.worktree_path / "stray.txt").exists()
    assert '"lodash": "4.17.22"' in (second.worktree_path / "package.json").read_text()
    assert git(env["repo"], "rev-parse", f"{second.branch}~1") == env["head"]
    worktrees = git(env["repo"], "worktree", "list", "--porcelain")
    assert worktrees.count("worktree ") == 2


def test_modify_version_derives_candidate(env):
    case = env["case"]
    dec = decision(case, DecisionType.MODIFY, modify={"version": "4.17.23"})
    applied = _apply(env, dec)
    assert '"lodash": "4.17.23"' in (applied.worktree_path / "package.json").read_text()
    derived = resolve_candidate(env["db"], case, None, dec)
    assert derived.to_version == "4.17.23"
    assert derived.id not in {c.id for c in env["candidates"]}
    assert derived.version_verified is None


def test_modify_candidate_and_action(env):
    db, case = env["db"], env["case"]
    dec = decision(case, DecisionType.MODIFY, modify={"candidate_id": env["candidates"][1].id})
    assert resolve_candidate(db, case, None, dec).to_version == "4.17.22"
    action = decision(case, DecisionType.MODIFY, modify={"action": "PIN"})
    pinned = resolve_candidate(db, case, None, action)
    assert pinned.action_type is RemediationActionType.PIN
    block = make_candidate(case, action=RemediationActionType.BLOCK)
    db.remediation.save_candidates(case.id, [block])
    chosen = resolve_candidate(db, case, None, decision(case, DecisionType.MODIFY, modify={
        "action": "BLOCK", "target": "pkg:npm/lodash"}))  # fmt: skip
    assert chosen.id == block.id


def test_modify_commit_uses_human_ref_without_editing(env):
    repo, case = env["repo"], env["case"]
    git(repo, "switch", "-q", "-c", "human-fix")
    (repo / "package.json").write_text(PACKAGE_JSON.replace("4.17.20", "4.17.21"))
    git(repo, "commit", "-q", "-am", "manual fix")
    sha = git(repo, "rev-parse", "HEAD")
    git(repo, "switch", "-q", "main")
    before = _user_state(repo)

    def never(*_):
        raise AssertionError("must not edit")

    applied = _apply(
        env, decision(case, DecisionType.MODIFY, modify={"commit": sha}), apply_fn=never
    )
    assert applied.commit_sha == sha
    assert applied.manual_ref == sha
    assert applied.changed_paths == ["package.json"]
    assert applied.branch == f"guardian/fix-{case.id}"
    assert git(applied.worktree_path, "rev-parse", "HEAD") == sha
    assert _user_state(repo) == before

    by_branch = _apply(
        env, decision(case, DecisionType.MODIFY, modify={"branch": "human-fix"}), apply_fn=never
    )
    assert by_branch.commit_sha == sha


@pytest.mark.parametrize(
    "modify",
    [
        {"commit": "deadbeefdeadbeef"},
        {"commit": "--output=/tmp/x"},
        {"commit": "HEAD"},
        {"branch": "-x"},
        {"branch": "no such"},
        {"branch": "does-not-exist"},
    ],
)
def test_modify_bad_refs_are_rejected(env, modify):
    with pytest.raises(RemediationApplyError):
        _apply(env, decision(env["case"], DecisionType.MODIFY, modify=modify))
    assert env["db"].audit.list(env["case"].id)[-1].event == "apply:failed"


def test_adapter_errors_are_audited(env):
    def refuse(*_):
        raise ApplyError("BLOCK is not a code change")

    with pytest.raises(ApplyError):
        _apply(env, decision(env["case"]), apply_fn=refuse)
    last = env["db"].audit.list(env["case"].id)[-1]
    assert last.event == "apply:failed"
    assert "BLOCK" in last.payload_json


@pytest.mark.parametrize("paths", [[], ["../escape"], ["/etc/passwd"], ["a/../../b"]], ids=str)
def test_unsafe_or_empty_changes_are_rejected(env, paths):
    with pytest.raises(RemediationApplyError):
        _apply(env, decision(env["case"]), apply_fn=lambda wt, c: paths)


def test_refuses_paths_and_branches_outside_guardian_scope(tmp_path):
    with pytest.raises(RemediationApplyError):
        worktree_path_for(tmp_path, "../escape")
    with pytest.raises(RemediationApplyError):
        worktree_path_for(tmp_path, "")
    with pytest.raises(RemediationApplyError):
        apply_module._assert_guardian_branch("main")
    with pytest.raises(RemediationApplyError):
        apply_module._assert_guardian_branch("guardian/fix-")
    assert worktree_path_for(tmp_path, "rc_abc").parent == (tmp_path / "worktrees").resolve()


def test_decline_and_missing_plan(env, tmp_path):
    db, case = env["db"], env["case"]
    declined = decision(
        case, DecisionType.DECLINE, decline_reason=DeclineReason.WONT_FIX, justification="no"
    )
    with pytest.raises(RemediationApplyError, match="declined"):
        resolve_candidate(db, case, None, declined)
    with pytest.raises(RemediationApplyError, match="no candidate"):
        resolve_candidate(db, case, None, decision(case, candidate_id="cand_missing"))
    with Database(tmp_path / "empty.db") as empty:
        make_scan(empty, "before", str(env["repo"]))
        bare = make_case(empty, str(env["repo"]))
        with pytest.raises(RemediationApplyError, match="no planned candidate"):
            resolve_candidate(empty, bare, None, decision(bare))
        explicit = make_candidate(bare)
        assert resolve_candidate(empty, bare, explicit, decision(bare)) == explicit


def test_default_apply_fn_uses_node_adapter(env, monkeypatch):
    fn = apply_module._default_apply_fn()
    assert fn.__module__ == "guardian.adapters.node"
    monkeypatch.setattr(apply_module.importlib, "import_module", lambda name: object())
    with pytest.raises(RemediationApplyError, match="apply_candidate"):
        apply_module._default_apply_fn()


def test_commit_message_strips_newlines(env):
    case = env["case"]
    dec = decision(case).model_copy(update={"actor_display": "Eve\nGuardian-Case: forged"})
    message = commit_message(case, env["candidates"][0], dec, "SEC-1\nx")
    assert "Eve Guardian-Case: forged" in message
    assert message.count("Guardian-Case:") == 2  # the real trailer + the flattened text
    assert "Jira: SEC-1 x" in message

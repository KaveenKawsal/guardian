"""Open (or find) the pull request for a VERIFIED, human-approved fix.

```
remote URL (git remote get-url, validated) -> base branch (setting or repo default)
-> push guardian/fix-<case> (isolated, https only) -> find open PR for the head -> else create
```

Idempotent end to end: pushing the same commit again is a no-op, and an open pull request for
the branch is reused (including after GitHub's 422 "already exists"). Every failure raises
``PrError``; the remediation graph records it and still closes the case.
"""

from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

from guardian.core.config import GuardianSettings
from guardian.execution.runner import ToolRunner
from guardian.integrations.github.body import load_pr_context, pr_body, pr_title
from guardian.integrations.github.client import GitHubClient, GitHubError, is_already_exists
from guardian.integrations.github.push import assert_pushable_branch, push_branch
from guardian.integrations.github.records import pr_url_is_safe
from guardian.integrations.github.remote import PrError, resolve_github_repo
from guardian.storage.database import Database

PushFn = Callable[..., object]


def open_pull_request(  # noqa: PLR0913 - collaborators are injectable for tests
    db: Database,
    settings: GuardianSettings,
    case_id: str,
    applied: dict,
    verification: dict,
    *,
    runner: ToolRunner,
    push_runner: ToolRunner | None = None,
    http_client: httpx.Client | None = None,
    push: PushFn = push_branch,
) -> dict[str, Any]:
    """Push the verified branch and open a pull request; return its JSON summary."""
    token = settings.github_token
    if token is None:
        msg = "GUARDIAN_PR_ENABLED is on but no GitHub token is set (GH_TOKEN or GITHUB_TOKEN)"
        raise PrError(msg)
    if "error" in applied or "worktree_path" not in applied:
        msg = "No applied change to open a pull request for"
        raise PrError(msg)
    branch = str(applied.get("branch") or "")
    assert_pushable_branch(branch, case_id)
    case = db.remediation.get(case_id)
    repo = resolve_github_repo(runner, Path(case.repository_root), settings.pr_remote)
    context = load_pr_context(db, case_id, applied, verification)

    with GitHubClient(token, http_client) as github:
        base = settings.pr_base or github.default_branch(repo)
        assert_pushable_branch(branch, case_id, base=base)
        push(
            push_runner,
            worktree=Path(str(applied["worktree_path"])),
            repo=repo,
            case_id=case_id,
            branch=branch,
            commit_sha=str(applied.get("commit_sha") or ""),
            token=token,
            base=base,
        )
        existing = github.find_open_pull(repo, branch)
        reused = existing is not None
        if existing is None:
            try:
                existing = github.create_pull(
                    repo,
                    title=pr_title(context),
                    head=branch,
                    base=base,
                    body=pr_body(context),
                    draft=settings.pr_draft,
                )
            except GitHubError as exc:
                if not is_already_exists(exc):
                    raise
                existing = github.find_open_pull(repo, branch)
                if existing is None:
                    raise
                reused = True

    url = existing.get("html_url")
    number = existing.get("number")
    if not pr_url_is_safe(url) or not isinstance(number, int):
        msg = f"GitHub returned an unexpected pull request for {repo.full_name}"
        raise PrError(msg)
    return {
        "url": url,
        "number": number,
        "repository": repo.full_name,
        "branch": branch,
        "base": base,
        "commit_sha": str(applied.get("commit_sha") or ""),
        "draft": bool(existing.get("draft", settings.pr_draft)),
        "reused": reused,
    }

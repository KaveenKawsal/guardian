"""Which GitHub repository a scanned repository belongs to, from its git remote.

Only ``https://github.com/<owner>/<repo>(.git)`` is accepted. SSH remotes, other hosts,
credentials embedded in the URL, query strings and anything else are refused: the URL comes
from the scanned (untrusted) repository's config, and the token is only ever sent to
github.com over https.
"""

import re
from dataclasses import dataclass
from pathlib import Path

from guardian.core.exceptions import GuardianError
from guardian.execution.runner import ToolRunner

GITHUB_HOST = "github.com"
GITHUB_ORIGIN = f"https://{GITHUB_HOST}"
_OWNER = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})"
_REPO = r"[A-Za-z0-9._-]{1,100}"
_REMOTE_RE = re.compile(
    rf"https://(?i:github\.com)/(?P<owner>{_OWNER})/(?P<repo>{_REPO}?)(?:\.git)?/?",
)
_REMOTE_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
_GIT_TIMEOUT = 60
MAX_SHOWN_URL = 120


class PrError(GuardianError):
    """Opening the pull request failed. Never contains the token."""


@dataclass(frozen=True)
class GitHubRepo:
    owner: str
    name: str

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"

    @property
    def push_url(self) -> str:
        """The canonical https URL (no credentials, ever)."""
        return f"{GITHUB_ORIGIN}/{self.owner}/{self.name}.git"

    @property
    def html_url(self) -> str:
        return f"{GITHUB_ORIGIN}/{self.owner}/{self.name}"


def _shown(url: str) -> str:
    """The URL for an error message, with any userinfo removed."""
    shown = re.sub(r"//[^/@\s]*@", "//***@", url.strip())
    return shown[:MAX_SHOWN_URL]


def parse_github_remote(url: str) -> GitHubRepo:
    """``https://github.com/<owner>/<repo>(.git)`` -> ``GitHubRepo``; anything else raises."""
    text = url.strip()
    if any(ch.isspace() or ord(ch) < 0x20 for ch in text):  # noqa: PLR2004 - control chars
        msg = "The git remote URL contains whitespace or control characters"
        raise PrError(msg)
    match = _REMOTE_RE.fullmatch(text)
    if match is None:
        msg = (
            f"Remote {_shown(text)!r} is not https://github.com/<owner>/<repo>; Guardian opens "
            "pull requests only for GitHub repositories over https (no ssh, no other hosts, "
            "no credentials in the URL)"
        )
        raise PrError(msg)
    repo = match.group("repo")
    if repo in {".", ".."} or repo.endswith(".git"):
        msg = f"Remote {_shown(text)!r} has an invalid repository name"
        raise PrError(msg)
    return GitHubRepo(owner=match.group("owner"), name=repo)


def resolve_github_repo(runner: ToolRunner, repo_root: Path, remote: str) -> GitHubRepo:
    """Read ``git remote get-url <remote>`` of the scanned repository and validate it."""
    if not _REMOTE_NAME_RE.fullmatch(remote):
        msg = f"Refusing unsafe git remote name {remote[:40]!r}"
        raise PrError(msg)
    result = runner.run(
        "git", ["remote", "get-url", remote], cwd=repo_root, timeout_seconds=_GIT_TIMEOUT
    )
    if not result.ok:
        detail = " ".join((result.stderr or result.error or "").split())[:200]
        msg = f"The scanned repository has no git remote {remote!r}: {detail}"
        raise PrError(msg)
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        msg = f"git remote {remote!r} has no single URL"
        raise PrError(msg)
    return parse_github_remote(lines[0])

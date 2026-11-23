"""Scan targets: parse what a user pasted and clone remote repositories safely.

A pasted target is untrusted text that ends up on a ``git`` command line, so it is parsed into a
small, validated structure first. Only public HTTPS repositories are cloned; every other git
transport (``file://``, ``ext::``, ``ssh://``, ``git://``, plain ``http://``) stays disabled by
the runner's git hardening, which this module only relaxes for ``https``.
"""

import hashlib
import os
import re
import shutil
import stat
import sys
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from guardian.core.config import GuardianSettings
from guardian.core.exceptions import GuardianError
from guardian.execution.results import ToolResult, ToolStatus
from guardian.execution.runner import ToolRunner


class InvalidTargetError(GuardianError):
    """The scan target is neither an existing directory nor a supported repository URL."""


class CloneError(GuardianError):
    """A remote repository could not be cloned."""


@dataclass(frozen=True)
class LocalTarget:
    path: Path

    @property
    def display(self) -> str:
        return str(self.path)


@dataclass(frozen=True)
class RemoteTarget:
    url: str
    """Normalized ``https://host[:port]/owner/repo`` URL, without a trailing ``.git``."""
    host: str
    """Host as written in the URL, including a non-default port."""
    path: str
    """Repository path on the host, e.g. ``owner/repo`` or ``group/subgroup/repo``."""
    ref: str | None = None

    @property
    def name(self) -> str:
        return self.path.rsplit("/", 1)[-1]

    @property
    def display(self) -> str:
        return f"{self.host}/{self.path}"

    def with_ref(self, ref: str | None) -> "RemoteTarget":
        if ref is None:
            return self
        return RemoteTarget(url=self.url, host=self.host, path=self.path, ref=_check_ref(ref))


Target = LocalTarget | RemoteTarget

_QUOTES = "\"'`"
_TRANSPORT_SYNTAX = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*::")
_SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*)://")
_SCP_LIKE = re.compile(r"^[^/\\\s]+@[^/\\\s]+:")
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SEGMENT = re.compile(r"^[A-Za-z0-9_.~-]+$")
_REF = re.compile(r"^[A-Za-z0-9._/+-]+$")
_GITHUB_OWNER = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})"
_GITHUB_REPO = r"[A-Za-z0-9._-]+"
_GITHUB_SHORTHAND = re.compile(rf"^(?:www\.)?github\.com/{_GITHUB_OWNER}/.+$", re.IGNORECASE)
_OWNER_REPO = re.compile(rf"^{_GITHUB_OWNER}/{_GITHUB_REPO}$")
_GITHUB_HOSTS = frozenset({"github.com", "www.github.com"})
_REF_MARKERS = frozenset({"tree", "blob", "src"})
_SSH_SCHEMES = frozenset({"ssh", "git+ssh", "ssh+git"})
_WINDOWS_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(10)} | {f"LPT{i}" for i in range(10)}
)

HTTPS_ONLY = "Guardian clones public repositories over HTTPS only for now"


def parse_target(text: str) -> Target:
    """Turn pasted text into a local directory or a validated remote repository."""
    cleaned = _clean(text)
    if not cleaned:
        msg = "No scan target given: paste a repository URL or a local path"
        raise InvalidTargetError(msg)
    if any(unicodedata.category(ch).startswith("C") for ch in cleaned):
        msg = "The scan target contains control characters"
        raise InvalidTargetError(msg)
    if _TRANSPORT_SYNTAX.match(cleaned):
        msg = f"Git transport syntax ('<transport>::') is not allowed. {HTTPS_ONLY}"
        raise InvalidTargetError(msg)
    if cleaned.startswith("-"):
        msg = "The scan target must not start with '-'"
        raise InvalidTargetError(msg)

    local = Path(cleaned).expanduser()
    if local.is_dir():
        return LocalTarget(local)

    if scheme := _SCHEME.match(cleaned):
        return _parse_url(cleaned, scheme.group(1).lower())
    if _SCP_LIKE.match(cleaned) and not _WINDOWS_DRIVE.match(cleaned):
        msg = f"SSH remotes (git@host:owner/repo) are not supported. {HTTPS_ONLY}"
        raise InvalidTargetError(msg)
    if any(ch.isspace() for ch in cleaned):
        msg = f"Not an existing directory or a repository URL: {cleaned}"
        raise InvalidTargetError(msg)
    if _GITHUB_SHORTHAND.match(cleaned):
        return _parse_url(f"https://{cleaned}", "https")
    if _OWNER_REPO.match(cleaned) and not cleaned.startswith("."):
        return _parse_url(f"https://github.com/{cleaned}", "https")
    if _looks_like_path(cleaned):
        msg = f"Local directory not found: {cleaned}"
        raise InvalidTargetError(msg)
    msg = (
        f"Not an existing directory or a supported repository: {cleaned} "
        "(expected a local path, https://host/owner/repo, github.com/owner/repo or owner/repo)"
    )
    raise InvalidTargetError(msg)


def _clean(text: str) -> str:
    cleaned = text.strip()
    while len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in _QUOTES:  # noqa: PLR2004
        cleaned = cleaned[1:-1].strip()
    return cleaned


def _looks_like_path(text: str) -> bool:
    return text.startswith((".", "/", "~")) or "\\" in text or bool(_WINDOWS_DRIVE.match(text))


def _parse_url(url: str, scheme: str) -> RemoteTarget:
    if scheme == "http":
        msg = "Plain http:// is insecure; use the https:// URL of the repository"
        raise InvalidTargetError(msg)
    if scheme == "file":
        msg = "file:// URLs are not allowed; pass the local directory path instead"
        raise InvalidTargetError(msg)
    if scheme in _SSH_SCHEMES:
        msg = f"SSH remotes are not supported. {HTTPS_ONLY}"
        raise InvalidTargetError(msg)
    if scheme != "https":
        msg = f"Unsupported URL scheme {scheme}://. {HTTPS_ONLY}"
        raise InvalidTargetError(msg)
    if any(ch.isspace() for ch in url):
        msg = "Repository URLs must not contain whitespace"
        raise InvalidTargetError(msg)

    parts = urlsplit(url)
    if "@" in parts.netloc:
        msg = (
            "The URL contains credentials (user@ or token@). Do not paste secrets: "
            "Guardian only clones public repositories"
        )
        raise InvalidTargetError(msg)
    host = _check_host(parts.hostname or "")
    try:
        port = parts.port
    except ValueError as exc:
        msg = "The URL has an invalid port"
        raise InvalidTargetError(msg) from exc
    netloc = host if port in {None, 443} else f"{host}:{port}"

    segments, ref = _split_repo_path(host, [s for s in parts.path.split("/") if s])
    if len(segments) < 2:  # noqa: PLR2004 - owner/repo
        msg = f"The URL does not point to a repository: expected https://{host}/owner/repo"
        raise InvalidTargetError(msg)
    if segments[-1].lower().endswith(".git"):
        segments[-1] = segments[-1][:-4]
    for segment in segments:
        if segment in {"", ".", ".."} or not _SEGMENT.match(segment):
            msg = f"Unsupported characters in repository path: {'/'.join(segments)}"
            raise InvalidTargetError(msg)
    path = "/".join(segments)
    return RemoteTarget(
        url=f"https://{netloc}/{path}",
        host=netloc,
        path=path,
        ref=_check_ref(ref) if ref else None,
    )


def _check_host(host: str) -> str:
    labels = host.split(".")
    if not host or len(host) > 253 or not all(_HOST_LABEL.match(label) for label in labels):  # noqa: PLR2004
        msg = "The URL has no valid host name"
        raise InvalidTargetError(msg)
    return host


def _split_repo_path(host: str, segments: list[str]) -> tuple[list[str], str | None]:
    """Separate the repository path from web-UI suffixes such as ``/tree/<ref>/dir``."""
    if "-" in segments:  # GitLab: /group/repo/-/tree/<ref>
        cut = segments.index("-")
        repo, rest = segments[:cut], segments[cut + 1 :]
    elif host in _GITHUB_HOSTS:
        repo, rest = segments[:2], segments[2:]
    else:
        cut = next(
            (i for i, s in enumerate(segments) if i >= 2 and s in _REF_MARKERS),  # noqa: PLR2004
            len(segments),
        )
        repo, rest = segments[:cut], segments[cut:]
    ref = rest[1] if len(rest) >= 2 and rest[0] in _REF_MARKERS else None  # noqa: PLR2004
    return repo, ref


def _check_ref(ref: str) -> str:
    ref = ref.strip()
    if (
        not _REF.match(ref)
        or ref.startswith(("-", "/", "."))
        or ref.endswith(("/", ".", ".lock"))
        or ".." in ref
        or "//" in ref
    ):
        msg = f"Invalid branch or tag name: {ref!r}"
        raise InvalidTargetError(msg)
    return ref


# --- cloning --------------------------------------------------------------------------------


def workspaces_dir(settings: GuardianSettings) -> Path:
    return settings.data_dir / "workspaces"


def workspace_path(target: RemoteTarget, settings: GuardianSettings) -> Path:
    """Stable clone location: the same repository always lands in the same directory.

    The directory is named after the repository, so the profile (and scan history) carry the
    repository name.
    """
    digest = hashlib.sha256(target.url.lower().encode()).hexdigest()[:12]
    return workspaces_dir(settings) / digest / _safe_dirname(target.name)


def _safe_dirname(name: str) -> str:
    name = name.rstrip(". ")
    if not name or name.split(".")[0].upper() in _WINDOWS_RESERVED:
        name = f"{name}_repo" if name else "repo"
    return name


def clone(
    target: RemoteTarget,
    settings: GuardianSettings,
    runner: ToolRunner,
    *,
    allow_file_transport: bool = False,
) -> Path:
    """Shallow-clone ``target`` into its workspace and return the checkout directory.

    ``allow_file_transport`` exists for tests that clone local repositories over ``file://``;
    the CLI never sets it.
    """
    dest = workspace_path(target, settings)
    remove_workspace(dest, settings)
    dest.parent.mkdir(parents=True, exist_ok=True)

    # The runner's hardening sets protocol.allow=never; the per-protocol key takes precedence
    # over it, so exactly one transport is re-enabled.
    protocol = "file" if allow_file_transport else "https"
    args = [
        "-c",
        f"protocol.{protocol}.allow=always",
        "-c",
        "core.symlinks=false",  # symlinks are checked out as plain files
        "-c",
        f"core.hooksPath={os.devnull}",
        "-c",
        "core.longpaths=true",
        "clone",
        "--depth",
        str(max(settings.change_history_commits, 1)),
        "--no-tags",
        "--single-branch",
        *(["--branch", target.ref] if target.ref else []),
        "--no-recurse-submodules",
        "--",
        target.url,
        str(dest),
    ]
    result = runner.run("git", args, cwd=dest.parent)
    if not result.ok:
        remove_workspace(dest, settings)
        raise CloneError(_clone_failure(target, result))
    return dest


def _clone_failure(target: RemoteTarget, result: ToolResult) -> str:
    if result.status is ToolStatus.NOT_FOUND:
        return "git is not installed or not on PATH; it is required to scan remote repositories"
    if result.status is ToolStatus.TIMEOUT:
        return f"Cloning {target.display} timed out ({result.error})"
    if result.status is ToolStatus.ERROR:
        return f"Could not run git to clone {target.display}"
    stderr = result.stderr.lower()
    if target.ref and "remote branch" in stderr and "not found" in stderr:
        return f"Branch or tag {target.ref!r} not found in {target.display}"
    checks: tuple[tuple[tuple[str, ...], str], ...] = (
        (
            (
                "terminal prompts disabled",
                "could not read username",
                "could not read password",
                "authentication failed",
                "repository not found",
                "error: 401",
                "error: 403",
                "error: 404",
                "not found",
            ),
            (
                f"Repository {target.display} not found or private "
                "(Guardian clones public HTTPS repositories)"
            ),
        ),
        (
            ("could not resolve host",),
            f"Could not resolve host {target.host}: check the URL and your network connection",
        ),
        (
            ("failed to connect", "connection timed out", "connection refused", "timed out"),
            f"Could not connect to {target.host}",
        ),
        (
            ("ssl", "certificate", "tls"),
            f"TLS/certificate error while connecting to {target.host}",
        ),
        (
            ("not allowed",),
            "The git transport is blocked by Guardian's execution policy",
        ),
    )
    for needles, message in checks:
        if any(n in stderr for n in needles):
            return message
    return f"git clone of {target.display} failed (exit code {result.exit_code})"


def remove_workspace(path: Path, settings: GuardianSettings) -> None:
    """Delete a clone; refuses anything that is not strictly inside the workspaces directory."""
    root = workspaces_dir(settings).resolve()
    if path.is_symlink():
        msg = f"Refusing to delete symlinked workspace {path}"
        raise CloneError(msg)
    resolved = path.resolve()
    if resolved == root or not resolved.is_relative_to(root):
        msg = f"Refusing to delete {path}: it is outside {root}"
        raise CloneError(msg)
    if not resolved.exists():
        return
    if sys.version_info >= (3, 12):
        shutil.rmtree(resolved, onexc=_make_writable_and_retry)
    else:  # pragma: no cover - exercised on Python 3.11 only
        shutil.rmtree(resolved, onerror=_make_writable_and_retry)


def _make_writable_and_retry(func: Callable[[str], object], path: str, _exc: object) -> None:
    """git marks pack files read-only, which ``rmtree`` cannot delete on Windows."""
    Path(path).chmod(stat.S_IWRITE | stat.S_IREAD)
    func(path)

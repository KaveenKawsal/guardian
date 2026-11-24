"""Minimal GitHub REST client for opening one pull request (httpx, injectable transport).

The token stays in ``SecretStr`` and in the ``Authorization`` header only; error messages carry
the method, path, status and GitHub's own message, scrubbed of the token. Redirects are not
followed, responses are size-capped, and GETs are retried with backoff on 429, on a rate-limit
403 and on 5xx. Creating a pull request is never retried: a lost answer is resolved by looking
the pull request up again (``find_open_pull``), which is what makes ``open_pull_request``
idempotent.
"""

import json
import logging
import re
import time
from collections.abc import Callable, Mapping
from typing import Any, Self
from urllib.parse import quote

import httpx
from pydantic import SecretStr

from guardian.integrations.github.remote import GitHubRepo, PrError

logger = logging.getLogger(__name__)

API_BASE = "https://api.github.com"
API_VERSION = "2022-11-28"
DEFAULT_TIMEOUT = httpx.Timeout(30.0, connect=10.0)
MAX_RETRIES = 3
BACKOFF_SECONDS = 1.0
MAX_RETRY_AFTER_SECONDS = 60.0
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
MAX_ERROR_CHARS = 300
HTTP_FORBIDDEN = 403
HTTP_UNPROCESSABLE = 422
HTTP_TOO_MANY_REQUESTS = 429
HTTP_SERVER_ERROR = 500
HTTP_CLIENT_ERROR = 400
_BRANCH_RE = re.compile(r"[A-Za-z0-9._/-]{1,200}")

JsonObject = dict[str, Any]


class GitHubError(PrError):
    """A GitHub API request failed. One line, never the token."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


def _branch(name: str) -> str:
    if not _BRANCH_RE.fullmatch(name) or name.startswith(("-", "/")) or ".." in name:
        msg = f"Invalid branch name {name[:80]!r}"
        raise GitHubError(msg)
    return name


class GitHubClient:
    def __init__(
        self,
        token: SecretStr,
        client: httpx.Client | None = None,
        *,
        sleep: Callable[[float], None] = time.sleep,
        max_retries: int = MAX_RETRIES,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
    ) -> None:
        self._token = token
        self._own_client = client is None
        self._http = client or httpx.Client(timeout=DEFAULT_TIMEOUT, follow_redirects=False)
        self._sleep = sleep
        self._max_retries = max_retries
        self._max_response_bytes = max_response_bytes

    def __repr__(self) -> str:
        return "GitHubClient(api.github.com)"

    def close(self) -> None:
        if self._own_client:
            self._http.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # --- endpoints ---------------------------------------------------------------------

    def user(self) -> JsonObject:
        return self._json("GET", "/user")

    def repository(self, repo: GitHubRepo) -> JsonObject:
        return self._json("GET", f"/repos/{repo.owner}/{repo.name}")

    def default_branch(self, repo: GitHubRepo) -> str:
        name = self.repository(repo).get("default_branch")
        if not isinstance(name, str) or not name:
            msg = f"GitHub GET /repos/{repo.full_name}: no default_branch in the response"
            raise GitHubError(msg)
        return _branch(name)

    def find_open_pull(self, repo: GitHubRepo, branch: str) -> JsonObject | None:
        """The open pull request whose head is ``<owner>:<branch>``, if any."""
        params = {"head": f"{repo.owner}:{_branch(branch)}", "state": "open", "per_page": "10"}
        data = self._request_json("GET", f"/repos/{repo.owner}/{repo.name}/pulls", params=params)
        if not isinstance(data, list):
            msg = f"GitHub GET /repos/{repo.full_name}/pulls: unexpected response"
            raise GitHubError(msg)
        for item in data:
            head = item.get("head") if isinstance(item, dict) else None
            if isinstance(head, dict) and head.get("ref") == branch:
                return item
        return None

    def create_pull(  # noqa: PLR0913 - the API's own fields
        self,
        repo: GitHubRepo,
        *,
        title: str,
        head: str,
        base: str,
        body: str,
        draft: bool,
    ) -> JsonObject:
        payload = {
            "title": title,
            "head": _branch(head),
            "base": _branch(base),
            "body": body,
            "draft": draft,
        }
        return self._json(
            "POST", f"/repos/{repo.owner}/{repo.name}/pulls", body=payload, retry=False
        )

    # --- transport ---------------------------------------------------------------------

    def _json(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, str] | None = None,
        body: Mapping[str, Any] | None = None,
        retry: bool = True,
    ) -> JsonObject:
        data = self._request_json(method, path, params=params, body=body, retry=retry)
        if not isinstance(data, dict):
            msg = f"GitHub {method} {path}: unexpected (non-object JSON) response"
            raise GitHubError(msg)
        return data

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, str] | None = None,
        body: Mapping[str, Any] | None = None,
        retry: bool = True,
    ) -> object:
        status, raw = self._request(method, path, params=params, body=body, retry=retry)
        try:
            return json.loads(raw) if raw else {}
        except ValueError as exc:
            msg = f"GitHub {method} {path}: response is not JSON"
            raise GitHubError(msg, status_code=status) from exc

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, str] | None,
        body: Mapping[str, Any] | None,
        retry: bool,
    ) -> tuple[int, bytes]:
        url = API_BASE + quote(path, safe="/")
        attempt = 0
        while True:
            reason = ""
            status: int | None = None
            headers: httpx.Headers | None = None
            raw = b""
            try:
                status, headers, raw = self._send(method, url, params, body)
            except httpx.TimeoutException:
                reason = "timed out"
            except httpx.TransportError as exc:
                reason = f"connection failed ({type(exc).__name__})"
            retryable = status is None or _retryable(status, headers)
            if status is not None and not retryable:
                if status >= HTTP_CLIENT_ERROR:
                    raise self._http_error(method, path, status, raw)
                return status, raw
            if not retry or attempt >= self._max_retries:
                if status is None:
                    msg = f"GitHub {method} {path}: {reason}"
                    raise GitHubError(msg)
                raise self._http_error(method, path, status, raw)
            delay = _retry_after(headers) if headers is not None else None
            if delay is None:
                delay = BACKOFF_SECONDS * (2**attempt)
            logger.debug("GitHub %s %s: retrying in %.1fs", method, path, delay)
            self._sleep(delay)
            attempt += 1

    def _send(
        self,
        method: str,
        url: str,
        params: Mapping[str, str] | None,
        body: Mapping[str, Any] | None,
    ) -> tuple[int, httpx.Headers, bytes]:
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._token.get_secret_value()}",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "guardian-remediation",
        }
        with self._http.stream(
            method,
            url,
            params=params,
            json=body,
            headers=headers,
            timeout=DEFAULT_TIMEOUT,
            follow_redirects=False,
        ) as response:
            raw = bytearray()
            for chunk in response.iter_bytes():
                raw += chunk
                if len(raw) > self._max_response_bytes:
                    msg = f"GitHub {method} {httpx.URL(url).path}: response too large"
                    raise GitHubError(msg, status_code=response.status_code)
            return response.status_code, response.headers, bytes(raw)

    def _http_error(self, method: str, path: str, status: int, raw: bytes) -> GitHubError:
        detail = self.scrub(_error_detail(raw))
        if len(detail) > MAX_ERROR_CHARS:
            detail = detail[:MAX_ERROR_CHARS] + "..."
        hint = {
            401: " (check GH_TOKEN)",
            403: " (token lacks permission: needs contents and pull requests write)",
            404: " (repository not found, or the token cannot see it)",
        }.get(status, "")
        msg = f"GitHub {method} {path}: HTTP {status}{hint}" + (f" - {detail}" if detail else "")
        return GitHubError(msg, status_code=status)

    def scrub(self, text: str) -> str:
        line = " ".join(text.split())
        secret = self._token.get_secret_value()
        return line.replace(secret, "***") if secret else line


def _retryable(status: int, headers: httpx.Headers | None) -> bool:
    if status == HTTP_TOO_MANY_REQUESTS or status >= HTTP_SERVER_ERROR:
        return True
    return (
        status == HTTP_FORBIDDEN
        and headers is not None
        and headers.get("x-ratelimit-remaining") == "0"
    )


def _retry_after(headers: httpx.Headers) -> float | None:
    value = headers.get("Retry-After")
    if value is None:
        return None
    try:
        seconds = float(value.strip())
    except ValueError:
        return None
    return min(max(seconds, 0.0), MAX_RETRY_AFTER_SECONDS)


def _error_detail(raw: bytes) -> str:
    try:
        data = json.loads(raw[:65536]) if raw else None
    except ValueError:
        return ""
    if not isinstance(data, dict):
        return ""
    parts = [str(data.get("message") or "")]
    for error in data.get("errors") or []:
        if isinstance(error, dict) and error.get("message"):
            parts.append(str(error["message"]))
        elif isinstance(error, str):
            parts.append(error)
    return "; ".join(p for p in parts[:5] if p)


def is_already_exists(error: GitHubError) -> bool:
    """GitHub's 422 for a second pull request from the same head."""
    return error.status_code == HTTP_UNPROCESSABLE and "already exists" in str(error).lower()

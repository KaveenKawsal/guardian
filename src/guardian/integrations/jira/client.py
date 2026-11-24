"""Thin Jira Cloud REST API v3 client (basic auth with an API token).

The token stays inside :class:`pydantic.SecretStr` and inside httpx's auth object; error
messages carry the method, path, HTTP status and Jira's own error strings only, scrubbed of
the token and the email, and never the request headers. Responses are size-capped, redirects
are not followed, and 429/5xx answers are retried with exponential backoff that honours
``Retry-After``.
"""

import base64
import json
import logging
import re
import time
from collections.abc import Callable, Iterator, Mapping
from typing import Any, Self
from urllib.parse import quote

import httpx
from pydantic import SecretStr

from guardian.core.config import GuardianSettings
from guardian.core.exceptions import ConfigurationError, GuardianError

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = httpx.Timeout(30.0, connect=10.0)
MAX_RETRIES = 3
BACKOFF_SECONDS = 1.0
MAX_RETRY_AFTER_SECONDS = 60.0
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
MAX_ERROR_CHARS = 300
MAX_PAGES = 50
HTTP_TOO_MANY_REQUESTS = 429
HTTP_SERVER_ERROR = 500
HTTP_NO_CONTENT = 204
HTTP_CLIENT_ERROR = 400

# Issue keys go into URL paths; anything else is refused before a request is built.
ISSUE_KEY_RE = re.compile(r"[A-Z][A-Z0-9_]{0,49}-[1-9][0-9]{0,9}")
COMMENT_ID_RE = re.compile(r"[0-9]{1,20}")

JsonObject = dict[str, Any]


class JiraError(GuardianError):
    """A Jira request failed. The message is one line and never contains credentials."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        field_errors: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.field_errors: dict[str, str] = dict(field_errors or {})


def validate_issue_key(key: str) -> str:
    if not isinstance(key, str) or not ISSUE_KEY_RE.fullmatch(key):
        msg = f"Invalid Jira issue key {str(key)[:40]!r}"
        raise JiraError(msg)
    return key


class JiraClient:
    def __init__(  # noqa: PLR0913 - injectable collaborators for tests
        self,
        base_url: str,
        email: str,
        token: SecretStr,
        client: httpx.Client | None = None,
        *,
        sleep: Callable[[float], None] = time.sleep,
        max_retries: int = MAX_RETRIES,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
    ) -> None:
        base = str(base_url).strip().rstrip("/")
        if not base.lower().startswith("https://"):
            msg = "Jira base URL must use https://"
            raise ConfigurationError(msg)
        self.base_url = base
        self._email = email
        self._token = token
        self._own_client = client is None
        self._http = client or httpx.Client(timeout=DEFAULT_TIMEOUT, follow_redirects=False)
        self._auth = httpx.BasicAuth(email, token.get_secret_value())
        self._sleep = sleep
        self._max_retries = max_retries
        self._max_response_bytes = max_response_bytes

    def __repr__(self) -> str:
        return f"JiraClient(base_url={self.base_url!r})"

    def close(self) -> None:
        if self._own_client:
            self._http.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # --- endpoints ---------------------------------------------------------------------

    def myself(self) -> JsonObject:
        return self._json("GET", "/rest/api/3/myself")

    def create_issue(self, fields: Mapping[str, Any]) -> str:
        data = self._json("POST", "/rest/api/3/issue", body={"fields": dict(fields)}, retry=False)
        key = data.get("key")
        if not isinstance(key, str):
            msg = "Jira POST /rest/api/3/issue: response has no issue key"
            raise JiraError(msg)
        return validate_issue_key(key)

    def update_issue(self, key: str, fields: Mapping[str, Any]) -> None:
        path = f"/rest/api/3/issue/{validate_issue_key(key)}"
        self._request("PUT", path, body={"fields": dict(fields)})

    def get_issue(self, key: str, fields: list[str] | None = None) -> JsonObject:
        params = {"fields": ",".join(fields)} if fields else None
        return self._json("GET", f"/rest/api/3/issue/{validate_issue_key(key)}", params=params)

    def search_jql(
        self,
        jql: str,
        fields: list[str] | None = None,
        next_page_token: str | None = None,
        *,
        max_results: int = 50,
    ) -> JsonObject:
        """One page of ``POST /rest/api/3/search/jql`` (the old ``/search`` is removed)."""
        body: JsonObject = {"jql": jql, "maxResults": max_results}
        if fields:
            body["fields"] = fields
        if next_page_token:
            body["nextPageToken"] = next_page_token
        return self._json("POST", "/rest/api/3/search/jql", body=body)

    def iter_search(
        self, jql: str, fields: list[str] | None = None, *, max_pages: int = MAX_PAGES
    ) -> Iterator[JsonObject]:
        token: str | None = None
        for _ in range(max_pages):
            page = self.search_jql(jql, fields, token)
            yield from (i for i in page.get("issues") or [] if isinstance(i, dict))
            token = page.get("nextPageToken")
            if not isinstance(token, str) or not token or page.get("isLast") is True:
                return

    def list_comments(self, key: str, start_at: int = 0, *, max_results: int = 100) -> JsonObject:
        params = {"startAt": str(start_at), "maxResults": str(max_results), "orderBy": "created"}
        path = f"/rest/api/3/issue/{validate_issue_key(key)}/comment"
        return self._json("GET", path, params=params)

    def iter_comments(self, key: str, *, max_pages: int = MAX_PAGES) -> Iterator[JsonObject]:
        start = 0
        for _ in range(max_pages):
            page = self.list_comments(key, start)
            comments = [c for c in page.get("comments") or [] if isinstance(c, dict)]
            yield from comments
            total = page.get("total")
            start += len(comments)
            if not comments or not isinstance(total, int) or start >= total:
                return

    def add_comment(self, key: str, adf: Mapping[str, Any]) -> str:
        path = f"/rest/api/3/issue/{validate_issue_key(key)}/comment"
        data = self._json("POST", path, body={"body": dict(adf)}, retry=False)
        comment_id = data.get("id")
        if not isinstance(comment_id, str):
            msg = f"Jira POST {path}: response has no comment id"
            raise JiraError(msg)
        return comment_id

    def get_transitions(self, key: str) -> list[JsonObject]:
        data = self._json("GET", f"/rest/api/3/issue/{validate_issue_key(key)}/transitions")
        return [t for t in data.get("transitions") or [] if isinstance(t, dict)]

    def transition(self, key: str, name: str) -> bool:
        """Move the issue through the transition called ``name`` (case-insensitive).

        Returns False when the workflow offers no such transition from the current status.
        """
        wanted = name.strip().casefold()
        for item in self.get_transitions(key):
            names = {str(item.get("name", "")).casefold()}
            to = item.get("to")
            if isinstance(to, dict):
                names.add(str(to.get("name", "")).casefold())
            if wanted in names and isinstance(item.get("id"), str):
                path = f"/rest/api/3/issue/{validate_issue_key(key)}/transitions"
                self._request("POST", path, body={"transition": {"id": item["id"]}})
                return True
        return False

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
        status, raw = self._request(method, path, params=params, body=body, retry=retry)
        if status == HTTP_NO_CONTENT or not raw:
            return {}
        try:
            data = json.loads(raw)
        except ValueError:
            data = None
        if not isinstance(data, dict):
            msg = f"Jira {method} {path}: unexpected (non-object JSON) response"
            raise JiraError(msg, status_code=status)
        return data

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, str] | None = None,
        body: Mapping[str, Any] | None = None,
        retry: bool = True,
    ) -> tuple[int, bytes]:
        """Send with retries. ``retry=False`` (non-idempotent POST) still retries 429,
        which Jira answers before doing any work."""
        url = self.base_url + quote(path, safe="/")
        attempt = 0
        while True:
            reason = ""
            try:
                status, headers, raw = self._send(method, url, params, body)
            except httpx.TimeoutException:
                reason = "timed out"
                status, headers, raw = None, None, b""
            except httpx.TransportError as exc:
                reason = f"connection failed ({type(exc).__name__})"
                status, headers, raw = None, None, b""
            if status is not None and not _retryable_status(status):
                if status >= HTTP_CLIENT_ERROR:
                    raise self._http_error(method, path, status, raw)
                return status, raw
            retryable = status == HTTP_TOO_MANY_REQUESTS or retry
            if attempt >= self._max_retries or not retryable:
                if status is None:
                    msg = f"Jira {method} {path}: {reason}"
                    raise JiraError(msg)
                raise self._http_error(method, path, status, raw)
            delay = _retry_after(headers) if headers is not None else None
            if delay is None:
                delay = BACKOFF_SECONDS * (2**attempt)
            logger.debug("Jira %s %s: retrying in %.1fs", method, path, delay)
            self._sleep(delay)
            attempt += 1

    def _send(
        self,
        method: str,
        url: str,
        params: Mapping[str, str] | None,
        body: Mapping[str, Any] | None,
    ) -> tuple[int, httpx.Headers, bytes]:
        with self._http.stream(
            method,
            url,
            params=params,
            json=body,
            auth=self._auth,
            headers={"Accept": "application/json"},
            timeout=DEFAULT_TIMEOUT,
            follow_redirects=False,
        ) as response:
            raw = bytearray()
            for chunk in response.iter_bytes():
                raw += chunk
                if len(raw) > self._max_response_bytes:
                    msg = (
                        f"Jira {method} {httpx.URL(url).path}: response larger than "
                        f"{self._max_response_bytes} bytes"
                    )
                    raise JiraError(msg, status_code=response.status_code)
            return response.status_code, response.headers, bytes(raw)

    def _http_error(self, method: str, path: str, status: int, raw: bytes) -> JiraError:
        messages, field_errors = _error_details(raw)
        detail = "; ".join([*messages, *(f"{k}: {v}" for k, v in field_errors.items())])
        detail = self._scrub(" ".join(detail.split()))
        if len(detail) > MAX_ERROR_CHARS:
            detail = detail[:MAX_ERROR_CHARS] + "..."
        hint = {401: " (check JIRA_EMAIL / JIRA_API_TOKEN)", 403: " (permission denied)"}.get(
            status, ""
        )
        msg = f"Jira {method} {path}: HTTP {status}{hint}" + (f" - {detail}" if detail else "")
        return JiraError(
            msg,
            status_code=status,
            field_errors={k: self._scrub(v) for k, v in field_errors.items()},
        )

    def _scrub(self, text: str) -> str:
        token = self._token.get_secret_value()
        basic = base64.b64encode(f"{self._email}:{token}".encode()).decode()
        for secret in (basic, token, self._email):
            if secret:
                text = text.replace(secret, "***")
        return text


def _retryable_status(status: int) -> bool:
    return status == HTTP_TOO_MANY_REQUESTS or status >= HTTP_SERVER_ERROR


def _retry_after(headers: httpx.Headers) -> float | None:
    value = headers.get("Retry-After")
    if value is None:
        return None
    try:
        seconds = float(value.strip())
    except ValueError:
        return None
    return min(max(seconds, 0.0), MAX_RETRY_AFTER_SECONDS)


def _error_details(raw: bytes) -> tuple[list[str], dict[str, str]]:
    try:
        data = json.loads(raw[:65536]) if raw else None
    except ValueError:
        return [], {}
    if not isinstance(data, dict):
        return [], {}
    messages = [str(m) for m in data.get("errorMessages") or [] if isinstance(m, str)][:5]
    errors = data.get("errors")
    fields = (
        {str(k): str(v) for k, v in list(errors.items())[:10]} if isinstance(errors, dict) else {}
    )
    return messages, fields


def jira_client_from_settings(
    settings: GuardianSettings, *, client: httpx.Client | None = None
) -> JiraClient:
    """Build a client from ``JIRA_*`` settings; ``ConfigurationError`` names what is missing."""
    base, email, token = settings.jira_base_url, settings.jira_email, settings.jira_api_token
    if base is None or email is None or token is None or settings.jira_project_key is None:
        missing = [
            name
            for name, value in (
                ("JIRA_BASE_URL", base),
                ("JIRA_EMAIL", email),
                ("JIRA_API_TOKEN", token),
                ("JIRA_PROJECT_KEY", settings.jira_project_key),
            )
            if value is None
        ]
        msg = f"Jira is not configured: set {', '.join(missing)} in ./.env or ~/.guardian/.env"
        raise ConfigurationError(msg)
    return JiraClient(str(base), email, token, client)

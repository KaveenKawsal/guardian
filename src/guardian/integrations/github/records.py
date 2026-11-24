"""Reading the pull request a case's audit trail records (``pr:opened`` / ``pr:failed``)."""

import json
from collections.abc import Sequence
from typing import Any

from guardian.core.remediation_models import AuditEvent

PR_OPENED_EVENT = "pr:opened"
PR_FAILED_EVENT = "pr:failed"
GITHUB_PREFIX = "https://github.com/"


def pr_url_is_safe(url: object) -> bool:
    """Only ``https://github.com/...`` URLs are ever shown as links."""
    return (
        isinstance(url, str)
        and url.startswith(GITHUB_PREFIX)
        and not any(ch.isspace() or ch in "\"'<>\\" for ch in url)
    )


def pull_request_of(events: Sequence[AuditEvent]) -> dict[str, Any] | None:
    """The last opened pull request, else the last failure reason, else None.

    An opened pull request whose URL is not ``https://github.com/...`` is dropped."""
    opened = [e for e in events if e.event == PR_OPENED_EVENT]
    if opened:
        payload = json.loads(opened[-1].payload_json)
        url = payload.get("url")
        if not pr_url_is_safe(url):
            return None
        return {
            "url": url,
            "number": payload.get("number"),
            "draft": bool(payload.get("draft")),
            "repository": payload.get("repository"),
            "base": payload.get("base"),
            "at": opened[-1].at.isoformat(),
        }
    failed = [e for e in events if e.event == PR_FAILED_EVENT]
    if failed:
        error = json.loads(failed[-1].payload_json).get("error")
        return {
            "url": None,
            "error": str(error or "unknown error"),
            "at": failed[-1].at.isoformat(),
        }
    return None

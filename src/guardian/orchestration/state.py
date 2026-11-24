"""State of the remediation graph (one LangGraph thread per case, ``thread_id = case_id``).

Values are plain JSON (str, int, dict, None) so ``SqliteSaver`` can persist them and a fresh
process can resume a thread without importing Guardian model classes into the checkpoint.
"""

from typing import TypedDict


class RemediationState(TypedDict, total=False):
    case_id: str
    attempt: int
    """1 for the first decision; ``publish_failure`` increments it before re-review."""
    decision: dict | None
    """The decision ``apply`` acts on (``HumanDecision`` as JSON). For REVALIDATE it is the
    previous ACCEPT/MODIFY decision, re-used unchanged."""
    received_decision: dict | None
    """The decision as received at the last ``await_decision`` resume (may be REVALIDATE)."""
    applied: dict | None
    """``AppliedChange`` as JSON, or ``{"error": ...}`` when the change could not be applied."""
    validation: dict | None
    verification: dict | None
    pull_request: dict | None
    """``{"url", "number", ...}`` once ``open_pr`` opened or found the pull request."""
    jira_key: str | None
    last_event: str | None
    error: str | None

"""Turn a decision form into a recorded ``HumanDecision`` (ADR 11, rules 8 and 11).

The form fields are rebuilt into a ``/guardian ...`` command line and parsed by the same strict
parser as Jira comments and ``guardian decide``; the approver is the local OS user, checked
against ``GUARDIAN_CLI_APPROVERS``. No LLM is involved anywhere on this path.
"""

import getpass
import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from guardian.core.config import GuardianSettings
from guardian.core.remediation_models import HumanDecision, RemediationCase
from guardian.integrations.decisions import (
    decision_applies,
    record_decision_transition,
    revalidate_ready,
)
from guardian.integrations.jira.authz import is_authorized_cli
from guardian.integrations.jira.commands import (
    GRAMMAR_HELP,
    CommandParseError,
    describe,
    parse_command,
    to_decision,
)
from guardian.storage.database import Database
from guardian.storage.remediation import SYSTEM_ACTOR, RemediationCaseNotFoundError

logger = logging.getLogger(__name__)

DecisionHandler = Callable[[RemediationCase, HumanDecision], None]
"""Reaction to a recorded decision. Runs in a background thread; may take minutes."""

ACTIONS = frozenset({"accept", "modify", "decline", "revalidate"})
_FIELDS = frozenset(
    {"action", "candidate_id", "version", "decline_reason", "until", "justification"}
)
_TOKEN_FIELDS = ("candidate_id", "version", "decline_reason", "until")
MAX_FIELD_CHARS = 2_000


class DecisionError(Exception):
    """A decision request that is refused; ``status`` is the HTTP status to answer with."""

    def __init__(self, status: int, message: str, *, grammar: bool = False) -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.grammar = grammar

    def to_json(self) -> dict[str, str]:
        body = {"error": self.message}
        if self.grammar:
            body["grammar"] = GRAMMAR_HELP
        return body


def current_user() -> str:
    return getpass.getuser()


def default_handler(settings: GuardianSettings) -> DecisionHandler:
    """The Jira sync's default reaction: move the case along the state machine.

    Opens its own connection because it runs on a worker thread."""

    def handle(case: RemediationCase, decision: HumanDecision) -> None:
        with Database(settings.database_path) as db:
            record_decision_transition(db, case, decision)

    return handle


def _text(body: dict[str, Any], name: str) -> str | None:
    value = body.get(name)
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise DecisionError(400, f"{name} must be a string")
    if len(value) > MAX_FIELD_CHARS:
        raise DecisionError(400, f"{name} is longer than {MAX_FIELD_CHARS} characters")
    return value.strip() or None


def command_line(body: dict[str, Any]) -> str:
    """Build ``/guardian <action> key=value ... [-- justification]`` from the form fields.

    Values become single ``key=value`` tokens, so a value with whitespace (which would smuggle
    a second argument past the parser) is refused here. The parser checks everything else."""
    unknown = set(body) - _FIELDS
    if unknown:
        raise DecisionError(400, f"unknown field(s): {', '.join(sorted(unknown))}")
    action = body.get("action")
    if action not in ACTIONS:
        raise DecisionError(400, "action must be one of accept, modify, decline, revalidate")
    values = {name: _text(body, name) for name in _TOKEN_FIELDS}
    for name, value in values.items():
        if value is not None and any(ch.isspace() for ch in value):
            raise DecisionError(400, f"{name} must not contain spaces")
    justification = _text(body, "justification")

    tokens = ["/guardian", str(action)]
    if values["candidate_id"] is not None:
        tokens.append(f"candidate={values['candidate_id']}")
    if values["version"] is not None:
        tokens.append(f"version={values['version']}")
    if values["decline_reason"] is not None:
        tokens.append(f"reason={values['decline_reason'].lower()}")
    if values["until"] is not None:
        tokens.append(f"until={values['until']}")
    line = " ".join(tokens)
    if justification is not None:
        line += " -- " + justification
    return line


@dataclass(frozen=True, slots=True)
class Recorded:
    decision: HumanDecision
    summary: str
    status: str


class DecisionService:
    """Authorize, parse, record, then hand the decision to the handler on a worker thread."""

    def __init__(
        self,
        settings: GuardianSettings,
        handler: DecisionHandler | None = None,
        *,
        user: Callable[[], str] = current_user,
    ) -> None:
        self.settings = settings
        self.handler = handler or default_handler(settings)
        self._user = user
        self._lock = threading.Lock()
        self._pending: set[str] = set()
        self.threads: list[threading.Thread] = []

    def pending(self) -> frozenset[str]:
        with self._lock:
            return frozenset(self._pending)

    def submit(self, db: Database, case_id: str, body: dict[str, Any]) -> Recorded:
        try:
            case = db.remediation.get(case_id)
        except RemediationCaseNotFoundError as exc:
            raise DecisionError(404, f"No remediation case with id {case_id!r}") from exc
        line = command_line(body)
        user = self._user()
        if not is_authorized_cli(user, self.settings):
            db.audit.append(
                case.id, "cli:unauthorized", f"cli:{user}", {"command": line, "via": "ui"}
            )
            raise DecisionError(
                403,
                f"Local user {user!r} is not an approver. Add it to GUARDIAN_CLI_APPROVERS "
                "(comma-separated) and restart `guardian ui`. Nothing was recorded.",
            )
        try:
            parsed = parse_command(line)
        except CommandParseError as exc:
            raise DecisionError(400, f"Could not parse the decision: {exc}", grammar=True) from exc
        if not decision_applies(
            case, parsed.decision, can_revalidate=revalidate_ready(db, case.id)
        ):
            raise DecisionError(
                409,
                f"Case is {case.status.value}; a {parsed.decision.value.lower()} decision does "
                "not apply now. Nothing was recorded.",
            )
        with self._lock:
            if case.id in self._pending:
                raise DecisionError(
                    409,
                    "A decision for this case is already being processed. Nothing was recorded.",
                )
            self._pending.add(case.id)
        try:
            decision = to_decision(
                parsed,
                case_id=case.id,
                actor_id=user,
                actor_display=f"{user} (local UI)",
                channel="cli",
                comment_id=None,
                at=datetime.now(UTC),
            )
            db.remediation.save_decision(decision)
            db.audit.append(case.id, "decision:recorded", f"cli:{user}", decision)
        except BaseException:
            self._done(case.id)
            raise
        thread = threading.Thread(
            target=self._run, args=(case, decision), name=f"guardian-ui-{case.id}", daemon=True
        )
        self.threads.append(thread)
        thread.start()
        return Recorded(decision=decision, summary=describe(parsed), status=case.status.value)

    def _done(self, case_id: str) -> None:
        with self._lock:
            self._pending.discard(case_id)

    def _run(self, case: RemediationCase, decision: HumanDecision) -> None:
        try:
            self.handler(case, decision)
        except Exception as exc:  # noqa: BLE001 - recorded in the audit trail instead
            message = f"{type(exc).__name__}: {' '.join(str(exc).split())[:300]}"
            logger.warning("decision handler failed for %s: %s", case.id, message)
            try:
                with Database(self.settings.database_path) as db:
                    db.audit.append(
                        case.id, "decision:handler_failed", SYSTEM_ACTOR, {"error": message}
                    )
            except Exception:
                logger.exception("could not audit the handler failure for %s", case.id)
        finally:
            self._done(case.id)

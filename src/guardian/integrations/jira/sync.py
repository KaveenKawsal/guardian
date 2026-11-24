"""Poll Jira for ``/guardian`` decisions (no webhooks, so it works on a laptop).

One ``sync_once`` pass:

1. JQL ``project = KEY AND labels = guardian AND updated >= "<last sync - 1 min>"``
   (``/rest/api/3/search/jql``), the time in the Guardian account's own time zone, which is
   how Jira interprets JQL dates.
2. Each issue maps to a case through ``jira_links``; unknown issues are skipped.
3. Comments after ``last_synced_comment_id`` (numeric comparison) are read oldest first:
   Guardian's own comments and comments that are not ``/guardian`` commands are ignored;
   commands from accounts outside ``GUARDIAN_APPROVERS`` get one "not authorized" reply;
   parse errors get one reply with the grammar and change nothing; valid decisions are
   recorded (a comment id is recorded at most once), audited, acknowledged and handed to
   ``on_decision``. ``guardian jira sync`` passes the remediation graph
   (``runtime.submit_decision``), whose nodes make the status transitions; the sync itself
   never moves the case. Without a handler the legacy ``record_decision_transition`` is used.
4. ``last_synced_comment_id`` advances after every comment, and the sync time advances only
   when the whole pass succeeded, so a failed issue is retried next time.

Every reply is guarded by an audit event naming the comment id, so a re-sync of the same
comment never posts twice.
"""

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, tzinfo
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from guardian.core.config import GuardianSettings
from guardian.core.remediation_models import HumanDecision, JiraLink, RemediationCase
from guardian.integrations.decisions import (
    decision_applies,
    record_decision_transition,
    revalidate_ready,
)
from guardian.integrations.jira import adf
from guardian.integrations.jira.authz import is_authorized_jira
from guardian.integrations.jira.client import COMMENT_ID_RE, JiraClient, JiraError
from guardian.integrations.jira.commands import (
    GRAMMAR_HELP,
    CommandParseError,
    describe,
    is_command,
    parse_command,
    to_decision,
)
from guardian.storage.database import Database
from guardian.storage.remediation import SYSTEM_ACTOR

logger = logging.getLogger(__name__)

LAST_SYNC_KEY = "jira:last_sync_at"
SYNC_OVERLAP = timedelta(minutes=1)
MAX_DISPLAY_CHARS = 200
JIRA_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%f%z"

OnDecision = Callable[[RemediationCase, HumanDecision], None]


@dataclass(slots=True)
class SyncReport:
    issues_seen: int = 0
    comments_seen: int = 0
    decisions: list[HumanDecision] = field(default_factory=list)
    duplicates: int = 0
    parse_errors: int = 0
    unauthorized: int = 0
    ignored: int = 0
    """Guardian's own comments and comments that are not commands."""
    wrong_state: int = 0
    unlinked_issues: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


@dataclass(frozen=True, slots=True)
class _Comment:
    id: str
    author_id: str | None
    author_display: str
    created: datetime | None
    text: str


class JiraSync:
    def __init__(
        self,
        db: Database,
        jira: JiraClient,
        settings: GuardianSettings,
        on_decision: OnDecision | None = None,
        *,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.db = db
        self.jira = jira
        self.settings = settings
        self.on_decision: OnDecision = on_decision or self._default_on_decision
        self._sleep = sleep
        self._me: dict[str, Any] | None = None
        self._today = datetime.now(UTC).date()

    def _default_on_decision(self, case: RemediationCase, decision: HumanDecision) -> None:
        record_decision_transition(self.db, case, decision)

    # --- public --------------------------------------------------------------------------

    def sync_once(self, now: datetime | None = None) -> SyncReport:
        now = now or datetime.now(UTC)
        self._today = now.astimezone(UTC).date()
        report = SyncReport()
        if not self.settings.jira_project_key:
            report.errors.append("JIRA_PROJECT_KEY is not set")
            return report
        try:
            me = self._myself()
            issues = list(self.jira.iter_search(self._jql(me), ["key", "updated"]))
        except JiraError as exc:
            report.errors.append(str(exc))
            return report
        for issue in issues:
            key = issue.get("key")
            if not isinstance(key, str):
                continue
            report.issues_seen += 1
            link = self.db.remediation.jira_link_by_issue(key)
            if link is None:
                report.unlinked_issues.append(key)
                continue
            try:
                self._sync_issue(link, me, report)
            except JiraError as exc:
                report.errors.append(f"{key}: {exc}")
        if report.ok:
            self.db.kv.set(LAST_SYNC_KEY, now.astimezone(UTC).isoformat())
        return report

    def watch(
        self,
        *,
        on_report: Callable[[SyncReport], None] | None = None,
        max_iterations: int | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> int:
        """Poll every ``jira_poll_seconds`` until Ctrl-C (or ``max_iterations``).

        Returns the number of completed passes.
        """
        passes = 0
        try:
            while max_iterations is None or passes < max_iterations:
                report = self.sync_once(clock())
                passes += 1
                if on_report is not None:
                    on_report(report)
                if max_iterations is not None and passes >= max_iterations:
                    break
                self._sleep(self.settings.jira_poll_seconds)
        except KeyboardInterrupt:
            logger.info("Jira watch stopped after %d pass(es)", passes)
        return passes

    # --- one issue -----------------------------------------------------------------------

    def _myself(self) -> dict[str, Any]:
        if self._me is None:
            self._me = self.jira.myself()
        return self._me

    def _jql(self, me: dict[str, Any]) -> str:
        project = self.settings.jira_project_key or ""
        jql = f'project = "{_jql_escape(project)}" AND labels = guardian'
        last = self.db.kv.get(LAST_SYNC_KEY)
        if last:
            try:
                since = datetime.fromisoformat(last) - SYNC_OVERLAP
            except ValueError:
                return jql + " ORDER BY updated ASC"
            local = since.astimezone(_zone(me.get("timeZone")))
            jql += f' AND updated >= "{local.strftime("%Y-%m-%d %H:%M")}"'
        return jql + " ORDER BY updated ASC"

    def _sync_issue(self, link: JiraLink, me: dict[str, Any], report: SyncReport) -> None:
        last = _comment_number(link.last_synced_comment_id)
        comments = [c for c in self.jira.iter_comments(link.issue_key) if isinstance(c, dict)]
        parsed = [p for c in comments if (p := _comment(c)) is not None]
        fresh = sorted(
            (c for c in parsed if last is None or int(c.id) > last), key=lambda c: int(c.id)
        )
        for comment in fresh:
            report.comments_seen += 1
            self._handle(link, comment, me, report)
            self.db.remediation.set_last_synced_comment(link.case_id, comment.id)

    def _handle(
        self, link: JiraLink, comment: _Comment, me: dict[str, Any], report: SyncReport
    ) -> None:
        guardian_id = me.get("accountId") if isinstance(me.get("accountId"), str) else None
        if comment.author_id is not None and comment.author_id == guardian_id:
            report.ignored += 1
            return
        if not is_command(comment.text):
            report.ignored += 1
            return
        if not is_authorized_jira(
            comment.author_id, self.settings, guardian_account_id=guardian_id
        ):
            report.unauthorized += 1
            self._reply_once(
                link,
                comment,
                "jira:unauthorized",
                adf.doc(
                    adf.paragraph(
                        f"{comment.author_display}: not authorized to decide on Guardian "
                        "cases. The command was ignored."
                    )
                ),
            )
            return
        try:
            parsed = parse_command(comment.text, today=lambda: self._today)
        except CommandParseError as exc:
            report.parse_errors += 1
            self._reply_once(
                link,
                comment,
                "jira:parse_error",
                adf.doc(
                    adf.paragraph(adf.strong("Could not parse the command: "), str(exc)),
                    adf.paragraph("Nothing was changed. Valid commands:"),
                    adf.code_block(GRAMMAR_HELP),
                ),
                extra={"error": str(exc)},
            )
            return

        case = self.db.remediation.get(link.case_id)
        if not decision_applies(
            case, parsed.decision, can_revalidate=revalidate_ready(self.db, case.id)
        ):
            report.wrong_state += 1
            self._reply_once(
                link,
                comment,
                "jira:decision_ignored",
                adf.doc(
                    adf.paragraph(
                        f"Case is {case.status.value}; decision ignored ",
                        adf.code(describe(parsed)),
                        ".",
                    )
                ),
            )
            return

        decision = to_decision(
            parsed,
            case_id=case.id,
            actor_id=comment.author_id or "",
            actor_display=comment.author_display,
            channel="jira",
            comment_id=comment.id,
            at=comment.created or datetime.now(UTC),
        )
        if not self.db.remediation.save_decision(decision):
            report.duplicates += 1
            return
        self.db.audit.append(case.id, "decision:recorded", f"jira:{decision.actor_id}", decision)
        report.decisions.append(decision)
        self._reply_once(
            link,
            comment,
            "jira:acknowledged",
            adf.doc(
                adf.paragraph(
                    adf.strong("Decision acknowledged: "),
                    adf.code(describe(parsed)),
                    f" by {decision.actor_display}.",
                )
            ),
        )
        try:
            self.on_decision(case, decision)
        except Exception as exc:  # noqa: BLE001 - a failing handler must not stop the sync
            message = f"{type(exc).__name__}: {' '.join(str(exc).split())[:300]}"
            report.errors.append(f"{link.issue_key}: decision handler failed ({message})")
            self.db.audit.append(
                case.id, "decision:handler_failed", SYSTEM_ACTOR, {"error": message}
            )

    def _reply_once(
        self,
        link: JiraLink,
        comment: _Comment,
        event: str,
        body: adf.Node,
        *,
        extra: dict[str, str] | None = None,
    ) -> None:
        if any(
            e.event == event and f'"comment_id":"{comment.id}"' in e.payload_json
            for e in self.db.audit.list(link.case_id)
        ):
            return
        reply_id = self.jira.add_comment(link.issue_key, body)
        self.db.audit.append(
            link.case_id,
            event,
            SYSTEM_ACTOR,
            {
                "issue_key": link.issue_key,
                "comment_id": comment.id,
                "author_id": comment.author_id,
                "reply_id": reply_id,
                **(extra or {}),
            },
        )


# --- helpers ------------------------------------------------------------------------------


def _jql_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _zone(name: object) -> tzinfo:
    if isinstance(name, str) and name:
        try:
            return ZoneInfo(name)
        except (ZoneInfoNotFoundError, ValueError):
            pass
    return UTC


def _comment_number(comment_id: str | None) -> int | None:
    if comment_id is None or not COMMENT_ID_RE.fullmatch(comment_id):
        return None
    return int(comment_id)


def _comment(raw: dict[str, Any]) -> _Comment | None:
    comment_id = raw.get("id")
    if not isinstance(comment_id, str) or not COMMENT_ID_RE.fullmatch(comment_id):
        return None
    raw_author = raw.get("author")
    author: dict[str, Any] = raw_author if isinstance(raw_author, dict) else {}
    author_id = author.get("accountId") if isinstance(author.get("accountId"), str) else None
    display = author.get("displayName")
    display = adf.clean_text(display if isinstance(display, str) else author_id or "unknown")
    created: datetime | None = None
    if isinstance(raw.get("created"), str):
        try:
            created = datetime.strptime(raw["created"], JIRA_TIME_FORMAT)  # noqa: DTZ007 - %z
        except ValueError:
            created = None
    return _Comment(
        id=comment_id,
        author_id=author_id,
        author_display=display[:MAX_DISPLAY_CHARS],
        created=created,
        text=adf.adf_to_text(raw.get("body")),
    )

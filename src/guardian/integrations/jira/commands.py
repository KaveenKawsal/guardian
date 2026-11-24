"""Strict, deterministic parser for ``/guardian`` decision commands (ADR 11, rule 11).

Jira comments are untrusted text. No LLM, no ``eval``; tokens are split on whitespace and each
value is checked with a bounded, anchored pattern after a length check, so there is no input
for which parsing is slow. Every rejection is a :class:`CommandParseError` with a one-line
reason that Guardian echoes back to the commenter together with :data:`GRAMMAR_HELP`.
"""

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Literal, NoReturn

from packageurl import PackageURL

from guardian.core.exceptions import GuardianError
from guardian.core.remediation_models import (
    DecisionType,
    DeclineReason,
    HumanDecision,
    ModifyPayload,
    RemediationActionType,
)

PREFIX = "/guardian"
MAX_TEXT_CHARS = 10_000
MAX_LINE_CHARS = 1_000
MAX_TOKEN_CHARS = 256
MAX_JUSTIFICATION_CHARS = 2_000
MAX_BRANCH_CHARS = 200
MAX_VERSION_CHARS = 64
MAX_PURL_CHARS = 512

GRAMMAR_HELP = """\
/guardian accept
/guardian accept candidate=<cand_xxxxxxxxxxxx>
/guardian modify version=<x.y.z>
/guardian modify action=<PIN|REMOVE|REPLACE|UPGRADE|UPDATE_BASE_IMAGE|BLOCK|ESCALATE> \
[target=<purl>]
/guardian modify branch=<branch>
/guardian modify commit=<sha>
/guardian decline reason=<false_positive|accepted_risk|wont_fix|duplicate> [until=YYYY-MM-DD] \
-- <justification>
/guardian revalidate
(accepted_risk needs until= with a future date and a justification after --)"""

_CANDIDATE_RE = re.compile(r"cand_[0-9a-f]{12}")
_SEMVER_RE = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
_COMMIT_RE = re.compile(r"[0-9a-f]{7,40}")
_DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_BRANCH_CHARS_RE = re.compile(r"[A-Za-z0-9._/-]+")
# Jira's editor turns " -- " into an en or em dash; accept all three as the separator.
_SEPARATORS = frozenset({"--", "\u2013", "\u2014"})
_VERBS: dict[str, DecisionType] = {
    "accept": DecisionType.ACCEPT,
    "modify": DecisionType.MODIFY,
    "decline": DecisionType.DECLINE,
    "revalidate": DecisionType.REVALIDATE,
}
_REASONS: dict[str, DeclineReason] = {r.value.lower(): r for r in DeclineReason}
_ALLOWED_KEYS: dict[DecisionType, frozenset[str]] = {
    DecisionType.ACCEPT: frozenset({"candidate"}),
    DecisionType.MODIFY: frozenset({"version", "action", "target", "branch", "commit"}),
    DecisionType.DECLINE: frozenset({"reason", "until"}),
    DecisionType.REVALIDATE: frozenset(),
}


class CommandParseError(GuardianError):
    """The comment is a ``/guardian`` command but does not follow the grammar."""


@dataclass(frozen=True, slots=True)
class ParsedCommand:
    decision: DecisionType
    candidate_id: str | None = None
    modify: ModifyPayload | None = None
    decline_reason: DeclineReason | None = None
    until: date | None = None
    justification: str | None = None


def first_line(text: str) -> str | None:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return None


def is_command(text: str) -> bool:
    """True when the first non-empty line is a ``/guardian`` command (case-sensitive)."""
    line = first_line(_normalise(text[:MAX_TEXT_CHARS]))
    if line is None or not line.startswith(PREFIX):
        return False
    rest = line[len(PREFIX) :]
    return not rest or rest[0].isspace()


def parse_command(text: str, *, today: Callable[[], date] | None = None) -> ParsedCommand:
    """Parse a comment whose first non-empty line is a ``/guardian`` command."""
    if len(text) > MAX_TEXT_CHARS:
        _fail(f"comment is longer than {MAX_TEXT_CHARS} characters")
    text = _normalise(text)
    if not is_command(text):
        _fail("the first line must start with /guardian")
    lines = text.splitlines()
    index = next(i for i, line in enumerate(lines) if line.strip())
    line = lines[index].strip()
    if len(line) > MAX_LINE_CHARS:
        _fail(f"the command line is longer than {MAX_LINE_CHARS} characters")

    tokens, justification = _split_justification(line.split(), lines[index + 1 :])
    separated = justification is not None or len(tokens) != len(line.split())
    if len(tokens) < 2:  # noqa: PLR2004 - "/guardian <verb>"
        _fail("missing action: use accept, modify, decline or revalidate")
    verb = _VERBS.get(tokens[1])
    if verb is None:
        _fail(f"unknown action {_show(tokens[1])}: use accept, modify, decline or revalidate")
    args = _key_values(tokens[2:], verb)

    if separated and verb is not DecisionType.DECLINE:
        _fail("'-- <justification>' is only valid for decline")
    if justification is not None and len(justification) > MAX_JUSTIFICATION_CHARS:
        _fail(f"justification is longer than {MAX_JUSTIFICATION_CHARS} characters")

    if verb is DecisionType.ACCEPT:
        candidate = args.get("candidate")
        if candidate is not None and not _CANDIDATE_RE.fullmatch(candidate):
            _fail("candidate= must look like cand_ followed by 12 lowercase hex digits")
        return ParsedCommand(decision=verb, candidate_id=candidate)
    if verb is DecisionType.MODIFY:
        return ParsedCommand(decision=verb, modify=_modify(args))
    if verb is DecisionType.DECLINE:
        return _decline(args, justification, (today or _utc_today)())
    return ParsedCommand(decision=verb)


def to_decision(  # noqa: PLR0913, PLR0917 - one argument per HumanDecision field the parser cannot know
    parsed: ParsedCommand,
    case_id: str,
    actor_id: str,
    actor_display: str,
    channel: Literal["jira", "cli"],
    comment_id: str | None,
    at: datetime,
) -> HumanDecision:
    return HumanDecision(
        case_id=case_id,
        decision=parsed.decision,
        candidate_id=parsed.candidate_id,
        modify=parsed.modify,
        decline_reason=parsed.decline_reason,
        risk_acceptance_expires=parsed.until,
        justification=parsed.justification,
        actor_id=actor_id,
        actor_display=actor_display,
        channel=channel,
        jira_comment_id=comment_id,
        decided_at=at,
    )


def describe(parsed: ParsedCommand) -> str:
    """Short human-readable echo of a parsed command, e.g. for the acknowledgement."""
    parts = [parsed.decision.value.lower()]
    if parsed.candidate_id:
        parts.append(f"candidate={parsed.candidate_id}")
    if parsed.modify is not None:
        kind = parsed.modify.kind
        value = getattr(parsed.modify, kind)
        parts.append(f"{'candidate' if kind == 'candidate_id' else kind}={value}")
        if parsed.modify.target:
            parts.append(f"target={parsed.modify.target}")
    if parsed.decline_reason is not None:
        parts.append(f"reason={parsed.decline_reason.value.lower()}")
    if parsed.until is not None:
        parts.append(f"until={parsed.until.isoformat()}")
    return " ".join(parts)


# --- helpers ------------------------------------------------------------------------------


def _fail(message: str) -> NoReturn:
    raise CommandParseError(message)


def _show(token: str) -> str:
    return repr(token[:40] + ("..." if len(token) > 40 else ""))  # noqa: PLR2004


def _utc_today() -> date:
    return datetime.now(UTC).date()


def _normalise(text: str) -> str:
    # Non-breaking and other Unicode spaces from rich-text editors behave like spaces.
    return text.replace("\u00a0", " ").replace("\u202f", " ").replace("\u2007", " ")


def _split_justification(
    tokens: list[str], following_lines: list[str]
) -> tuple[list[str], str | None]:
    """Split ``... -- text`` into the argument tokens and the justification (the rest of the
    line plus any following lines)."""
    separator = next((i for i, t in enumerate(tokens) if t in _SEPARATORS), None)
    if separator is None:
        return tokens, None
    tail = " ".join(tokens[separator + 1 :])
    following = "\n".join(following_lines).strip()
    return tokens[:separator], "\n".join(p for p in (tail, following) if p).strip() or None


def _key_values(tokens: list[str], verb: DecisionType) -> dict[str, str]:
    allowed = _ALLOWED_KEYS[verb]
    args: dict[str, str] = {}
    for token in tokens:
        if len(token) > MAX_TOKEN_CHARS + MAX_PURL_CHARS:
            _fail("argument is too long")
        key, sep, value = token.partition("=")
        if not sep:
            _fail(f"unexpected argument {_show(token)}; arguments look like key=value")
        if key not in allowed:
            valid = ", ".join(sorted(allowed)) or "none"
            _fail(f"unknown argument {_show(key)} for {verb.value.lower()} (valid: {valid})")
        if key in args:
            _fail(f"duplicate argument {key}=")
        if not value:
            _fail(f"{key}= needs a value")
        args[key] = value
    return args


def _modify(args: dict[str, str]) -> ModifyPayload:
    kinds = [k for k in ("version", "action", "branch", "commit") if k in args]
    if len(kinds) != 1:
        _fail("modify needs exactly one of version=, action=, branch=, commit=")
    if "target" in args and "action" not in args:
        _fail("target= is only valid together with action=")
    kind = kinds[0]
    value = args[kind]
    if kind == "version":
        if len(value) > MAX_VERSION_CHARS or not _SEMVER_RE.fullmatch(value):
            _fail("version= must be a semantic version such as 1.2.3")
        return ModifyPayload(version=value)
    if kind == "action":
        try:
            action = RemediationActionType(value.upper())
        except ValueError:
            valid = "|".join(a.value for a in RemediationActionType)
            _fail(f"action= must be one of {valid}")
        target = args.get("target")
        if target is not None:
            _check_purl(target)
        return ModifyPayload(action=action, target=target)
    if kind == "branch":
        _check_branch(value)
        return ModifyPayload(branch=value)
    if not _COMMIT_RE.fullmatch(value):
        _fail("commit= must be 7-40 lowercase hex digits")
    return ModifyPayload(commit=value)


def _decline(args: dict[str, str], justification: str | None, today: date) -> ParsedCommand:
    reason_text = args.get("reason")
    if reason_text is None:
        _fail("decline needs reason=false_positive|accepted_risk|wont_fix|duplicate")
    reason = _REASONS.get(reason_text)
    if reason is None:
        _fail("reason= must be one of false_positive, accepted_risk, wont_fix, duplicate")
    until: date | None = None
    if (raw := args.get("until")) is not None:
        until = _future_date(raw, today)
    if reason is DeclineReason.ACCEPTED_RISK:
        if until is None:
            _fail("accepted_risk needs until=YYYY-MM-DD (the date the acceptance expires)")
        if not justification:
            _fail("accepted_risk needs a justification after --")
    return ParsedCommand(
        decision=DecisionType.DECLINE,
        decline_reason=reason,
        until=until,
        justification=justification,
    )


def _future_date(raw: str, today: date) -> date:
    if not _DATE_RE.fullmatch(raw):
        _fail("until= must be a date in the form YYYY-MM-DD")
    try:
        value = date.fromisoformat(raw)
    except ValueError:
        _fail(f"until={raw} is not a valid date")
    if value <= today:
        _fail(f"until= must be in the future (after {today.isoformat()})")
    return value


def _check_branch(name: str) -> None:
    """A conservative subset of ``git check-ref-format --branch``."""
    if len(name) > MAX_BRANCH_CHARS:
        _fail(f"branch= is longer than {MAX_BRANCH_CHARS} characters")
    if not _BRANCH_CHARS_RE.fullmatch(name):
        _fail("branch= may only contain letters, digits, '.', '_', '-' and '/'")
    if (
        name.startswith(("-", "/", "."))
        or name.endswith(("/", ".", ".lock"))
        or ".." in name
        or "//" in name
        or "/." in name
        or name == "HEAD"
    ):
        _fail(f"branch={name} is not a valid git branch name")


def _check_purl(value: str) -> None:
    if len(value) > MAX_PURL_CHARS or not value.startswith("pkg:"):
        _fail("target= must be a package URL such as pkg:npm/lodash@4.17.21")
    try:
        PackageURL.from_string(value)
    except ValueError:
        _fail("target= is not a valid package URL")

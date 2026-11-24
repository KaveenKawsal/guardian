import random
import string
from datetime import UTC, date, datetime

import pytest

from guardian.core.remediation_models import (
    DecisionType,
    DeclineReason,
    RemediationActionType,
)
from guardian.integrations.jira.commands import (
    GRAMMAR_HELP,
    CommandParseError,
    ParsedCommand,
    describe,
    is_command,
    parse_command,
    to_decision,
)

TODAY = date(2026, 11, 24)


def parse(text):
    return parse_command(text, today=lambda: TODAY)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("/guardian accept", ParsedCommand(DecisionType.ACCEPT)),
        ("  \n\n  /guardian accept  \nthanks!", ParsedCommand(DecisionType.ACCEPT)),
        (
            "/guardian accept candidate=cand_0123456789ab",
            ParsedCommand(DecisionType.ACCEPT, candidate_id="cand_0123456789ab"),
        ),
        ("/guardian revalidate", ParsedCommand(DecisionType.REVALIDATE)),
        ("/guardian\u00a0accept", ParsedCommand(DecisionType.ACCEPT)),
    ],
)
def test_simple_commands(text, expected):
    assert parse(text) == expected


@pytest.mark.parametrize(
    ("args", "kind", "value"),
    [
        ("version=4.2.2", "version", "4.2.2"),
        ("version=1.0.0-rc.1+build.5", "version", "1.0.0-rc.1+build.5"),
        ("branch=guardian/manual-fix", "branch", "guardian/manual-fix"),
        ("branch=fix_1.2", "branch", "fix_1.2"),
        ("commit=abc1234", "commit", "abc1234"),
        ("commit=" + "a" * 40, "commit", "a" * 40),
    ],
)
def test_modify(args, kind, value):
    parsed = parse(f"/guardian modify {args}")
    assert parsed.decision is DecisionType.MODIFY
    assert parsed.modify is not None
    assert parsed.modify.kind == kind
    assert getattr(parsed.modify, kind) == value


def test_modify_action_with_target():
    parsed = parse("/guardian modify action=replace target=pkg:npm/jose@5.0.0")
    assert parsed.modify is not None
    assert parsed.modify.action is RemediationActionType.REPLACE
    assert parsed.modify.target == "pkg:npm/jose@5.0.0"
    assert parse("/guardian modify action=ESCALATE").modify.action is RemediationActionType.ESCALATE


def test_decline_accepted_risk():
    parsed = parse(
        "/guardian decline reason=accepted_risk until=2027-06-30 -- intentional training vuln\n"
        "owned by the challenge team"
    )
    assert parsed.decline_reason is DeclineReason.ACCEPTED_RISK
    assert parsed.until == date(2027, 6, 30)
    assert parsed.justification == "intentional training vuln\nowned by the challenge team"


@pytest.mark.parametrize("dash", ["--", "\u2013", "\u2014"])
def test_jira_editor_dashes_are_separators(dash):
    parsed = parse(f"/guardian decline reason=wont_fix {dash} not used")
    assert parsed.justification == "not used"


def test_decline_without_justification_for_other_reasons():
    parsed = parse("/guardian decline reason=duplicate")
    assert parsed.decline_reason is DeclineReason.DUPLICATE
    assert parsed.justification is None


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("/Guardian accept", "must start with /guardian"),
        ("/guardianaccept", "must start with /guardian"),
        ("please /guardian accept", "must start with /guardian"),
        ("/guardian", "missing action"),
        ("/guardian approve", "unknown action"),
        ("/guardian ACCEPT", "unknown action"),
        ("/guardian accept now", "unexpected argument"),
        ("/guardian accept candidate=cand_XYZ", "candidate="),
        ("/guardian accept version=1.2.3", "unknown argument"),
        ("/guardian accept candidate=cand_0123456789ab candidate=cand_0123456789ab", "duplicate"),
        ("/guardian accept candidate=", "needs a value"),
        ("/guardian accept -- because", "only valid for decline"),
        ("/guardian modify", "exactly one of"),
        ("/guardian modify version=1.2.3 commit=abcdef1", "exactly one of"),
        ("/guardian modify version=1.2", "semantic version"),
        ("/guardian modify version=01.2.3", "semantic version"),
        ("/guardian modify action=DELETE", "action= must be one of"),
        ("/guardian modify version=1.2.3 target=pkg:npm/x@1", "only valid together with action"),
        ("/guardian modify action=PIN target=npm/x", "package URL"),
        ("/guardian modify action=PIN target=pkg:", "package URL"),
        ("/guardian modify branch=-evil", "not a valid git branch"),
        ("/guardian modify branch=a..b", "not a valid git branch"),
        ("/guardian modify branch=x.lock", "not a valid git branch"),
        ("/guardian modify branch=a//b", "not a valid git branch"),
        ("/guardian modify branch=a/.hidden", "not a valid git branch"),
        ("/guardian modify branch=HEAD", "not a valid git branch"),
        ("/guardian modify branch=a;rm", "may only contain"),
        ("/guardian modify branch=" + "a" * 201, "longer than"),
        ("/guardian modify commit=xyz1234", "hex"),
        ("/guardian modify commit=ABCDEF1", "hex"),
        ("/guardian decline", "needs reason="),
        ("/guardian decline reason=meh", "reason= must be one of"),
        ("/guardian decline reason=accepted_risk -- ok", "needs until="),
        ("/guardian decline reason=accepted_risk until=2027-01-01", "justification"),
        ("/guardian decline reason=accepted_risk until=2027-01-01 --", "justification"),
        ("/guardian decline reason=accepted_risk until=2026-11-24 -- x", "in the future"),
        ("/guardian decline reason=accepted_risk until=2027-02-30 -- x", "not a valid date"),
        ("/guardian decline reason=accepted_risk until=27-1-1 -- x", "YYYY-MM-DD"),
        ("/guardian decline reason=wont_fix -- x\n" + "x" * 2001, "justification is longer"),
        ("/guardian revalidate now=1", "unknown argument"),
        ("/guardian accept " + "x" * 1000, "longer than"),
        ("/guardian accept\n" + "x" * 10_001, "longer than"),
    ],
)
def test_rejections(text, message):
    with pytest.raises(CommandParseError, match=message):
        parse(text)


def test_is_command():
    assert is_command("\n /guardian accept")
    assert is_command("/guardian")
    assert not is_command("/guardians accept")
    assert not is_command("lgtm")
    assert not is_command("")


def test_to_decision_and_describe():
    at = datetime(2026, 11, 24, tzinfo=UTC)
    parsed = parse("/guardian decline reason=accepted_risk until=2027-01-01 -- training app")
    decision = to_decision(parsed, "rc_1", "acct", "Alice", "jira", "10001", at)
    assert decision.risk_acceptance_expires == date(2027, 1, 1)
    assert decision.justification == "training app"
    assert decision.jira_comment_id == "10001"
    assert describe(parsed) == "decline reason=accepted_risk until=2027-01-01"
    assert describe(parse("/guardian accept candidate=cand_0123456789ab")) == (
        "accept candidate=cand_0123456789ab"
    )
    assert describe(parse("/guardian modify action=PIN target=pkg:npm/a@1.0.0")) == (
        "modify action=PIN target=pkg:npm/a@1.0.0"
    )
    modify = to_decision(parse("/guardian modify version=4.2.2"), "rc_1", "a", "A", "cli", None, at)
    assert modify.modify is not None
    assert modify.modify.version == "4.2.2"


def test_default_today_is_used():
    with pytest.raises(CommandParseError, match="in the future"):
        parse_command("/guardian decline reason=accepted_risk until=2000-01-01 -- x")


def test_grammar_help_lists_every_verb():
    for verb in ("accept", "modify", "decline", "revalidate"):
        assert f"/guardian {verb}" in GRAMMAR_HELP


ALPHABET = string.printable + "\u00a0\u2013\u2014\u00e9\u200b\U0001f600=/-_."
TOKENS = [
    "/guardian",
    "accept",
    "modify",
    "decline",
    "revalidate",
    "candidate=",
    "version=",
    "action=",
    "target=",
    "branch=",
    "commit=",
    "reason=",
    "until=",
    "--",
    "\u2013",
    "accepted_risk",
    "wont_fix",
    "cand_0123456789ab",
    "1.2.3",
    "PIN",
    "pkg:npm/a@1",
    "2027-01-01",
    "\n",
    " ",
    "=",
    "..",
    "\x00",
]


def test_fuzz_never_raises_anything_but_parse_error():
    rng = random.Random(20261124)  # noqa: S311 - reproducible fuzz, not crypto
    for i in range(4000):
        if i % 2:
            text = "".join(rng.choice(ALPHABET) for _ in range(rng.randint(0, 120)))
        else:
            text = " ".join(rng.choice(TOKENS) for _ in range(rng.randint(0, 10)))
            if rng.random() < 0.7:
                text = "/guardian " + text
        try:
            result = parse(text)
        except CommandParseError as exc:
            message = str(exc)
        else:
            message = None
            assert isinstance(result, ParsedCommand)
            assert is_command(text)
        if message is not None:
            assert message
            assert "\n" not in message

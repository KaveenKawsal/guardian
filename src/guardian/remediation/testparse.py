"""Parse ``node --test`` output (spec and TAP reporters) into counts and failing files."""

import re
from collections.abc import Iterable
from dataclasses import dataclass, field

EXPECTED_CHALLENGE_TEST_FILES: frozenset[str] = frozenset({"test/server/rsn.unit.test.ts"})
"""Juice Shop test files that fail by design when a fix touches intentional challenge code."""

KNOWN_CONFLICT_DETAIL = "fix conflicts with intentional challenge code"

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_INFO = "\u2139"  # the spec reporter's "information source" glyph
_COUNT = re.compile(rf"^\s*(?:{_INFO}|#)\s+(tests|pass|fail)\s+(\d+)\s*$", re.MULTILINE)
_TEST_FILE = r"[^\s'\"()]+?\.(?:test|spec)\.[cm]?[jt]sx?"
_FILE_PATTERNS = (
    re.compile(rf"test at (?:file://)?({_TEST_FILE}):\d+"),
    re.compile(rf"location:\s*'(?:file://)?({_TEST_FILE}):\d+"),
    re.compile(rf"^\s*(?:✖|not ok \d+ -)\s+({_TEST_FILE})\b", re.MULTILINE),
)


@dataclass(frozen=True)
class TestSummary:
    __test__ = False  # not a pytest class

    discovered: int | None = None
    passed: int | None = None
    failed: int | None = None
    failing_files: tuple[str, ...] = field(default=())


def _normalize(path: str, roots: Iterable[str]) -> str:
    for root in roots:
        prefix = root.rstrip("/") + "/"
        if path.startswith(prefix):
            path = path[len(prefix) :]
            break
    else:
        if "/work/" in path:
            path = path.split("/work/", 1)[1]
    while path.startswith("./"):
        path = path[2:]
    return path


def parse_node_test_output(text: str, *, roots: Iterable[str] = ("/work",)) -> TestSummary:
    """Counts from the final summary block; failing test files from failure locations."""
    clean = _ANSI.sub("", text)
    counts: dict[str, int] = {}
    for key, value in _COUNT.findall(clean):
        counts[key] = int(value)  # the last summary wins (nested suites print their own)
    roots = tuple(roots)
    files: set[str] = set()
    for pattern in _FILE_PATTERNS:
        files.update(_normalize(m, roots) for m in pattern.findall(clean))
    failed = counts.get("fail")
    return TestSummary(
        discovered=counts.get("tests"),
        passed=counts.get("pass"),
        failed=failed,
        failing_files=tuple(sorted(files)) if failed != 0 else (),
    )


def is_known_conflict(
    summary: TestSummary, expected: frozenset[str] = EXPECTED_CHALLENGE_TEST_FILES
) -> bool:
    """True when every failing test file is an expected challenge-code test file."""
    return bool(summary.failing_files) and set(summary.failing_files) <= expected

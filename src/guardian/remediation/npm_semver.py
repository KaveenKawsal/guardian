"""Minimal npm-flavoured semantic versioning: parse, compare and ``satisfies``.

Covers what remediation needs from node-semver: exact versions, ``^``, ``~``, the comparison
operators, x-ranges (``1.x``, ``1.2.*``, ``*``), hyphen ranges, ``||`` and space-separated AND.
Prerelease versions only satisfy a range when one comparator of the matching set names the same
``major.minor.patch`` with a prerelease (npm's default, ``includePrerelease=false``).
Dist-tags (``latest``), URLs, git and file specifiers are not ranges: they never satisfy.
"""

import re
from dataclasses import dataclass
from functools import total_ordering
from typing import Literal

_VERSION_RE = re.compile(
    r"^\s*[v=]?\s*(\d+)\.(\d+)\.(\d+)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\s*$"
)
_PARTIAL_RE = re.compile(
    r"^[v=]?(?P<major>\d+|[xX*])(?:\.(?P<minor>\d+|[xX*])(?:\.(?P<patch>\d+|[xX*])"
    r"(?:-(?P<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)?)?$"
)
_OPERATOR_RE = re.compile(r"(>=|<=|>|<|=|\^|~>?)\s+")
_HYPHEN_RE = re.compile(r"^\s*(\S+)\s+-\s+(\S+)\s*$")
_SIMPLE_SPEC_RE = re.compile(r"^(?P<prefix>\^|~|>=|=|v)?\s*(?P<version>\d+\.\d+\.\d+\S*)$")
MAX_RANGE_CHARS = 1024

Jump = Literal["patch", "minor", "major"]


@total_ordering
@dataclass(frozen=True, slots=True)
class SemVer:
    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] = ()

    def __str__(self) -> str:
        core = f"{self.major}.{self.minor}.{self.patch}"
        return f"{core}-{'.'.join(self.prerelease)}" if self.prerelease else core

    @property
    def release(self) -> tuple[int, int, int]:
        return (self.major, self.minor, self.patch)

    @property
    def is_prerelease(self) -> bool:
        return bool(self.prerelease)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, SemVer):
            return NotImplemented
        if self.release != other.release:
            return self.release < other.release
        return _prerelease_lt(self.prerelease, other.prerelease)


def _prerelease_lt(a: tuple[str, ...], b: tuple[str, ...]) -> bool:
    """SemVer 2.0 precedence: a release sorts above its prereleases; numeric < alphanumeric."""
    if not a or not b:
        return bool(a) and not b
    for left, right in zip(a, b, strict=False):
        if left == right:
            continue
        left_num, right_num = left.isdigit(), right.isdigit()
        if left_num and right_num:
            return int(left) < int(right)
        if left_num != right_num:
            return left_num
        return left < right
    return len(a) < len(b)


def parse(text: str) -> SemVer | None:
    """A full ``major.minor.patch[-pre][+build]`` version, or None."""
    match = _VERSION_RE.match(text)
    if match is None:
        return None
    major, minor, patch, pre = match.groups()
    return SemVer(int(major), int(minor), int(patch), tuple(pre.split(".")) if pre else ())


def compare(a: str, b: str) -> int:
    """-1, 0 or 1; raises ValueError for an unparseable version."""
    left, right = parse(a), parse(b)
    if left is None or right is None:
        msg = f"Not a semantic version: {a if left is None else b!r}"
        raise ValueError(msg)
    return (left > right) - (left < right)


def jump(from_version: str, to_version: str) -> Jump | None:
    """Which release component changes first; None when either version is unparseable."""
    left, right = parse(from_version), parse(to_version)
    if left is None or right is None:
        return None
    if left.major != right.major:
        return "major"
    if left.minor != right.minor:
        return "minor"
    return "patch"


# --- Ranges ------------------------------------------------------------------------------

Op = Literal["<", "<=", ">", ">=", "="]


@dataclass(frozen=True, slots=True)
class Comparator:
    op: Op
    version: SemVer

    def test(self, v: SemVer) -> bool:
        if self.op == "<":
            return v < self.version
        if self.op == "<=":
            return v <= self.version
        if self.op == ">":
            return v > self.version
        if self.op == ">=":
            return v >= self.version
        return v == self.version


ComparatorSet = tuple[Comparator, ...]
_ANY: ComparatorSet = (Comparator(">=", SemVer(0, 0, 0)),)


@dataclass(frozen=True, slots=True)
class _Partial:
    major: int | None
    minor: int | None
    patch: int | None
    prerelease: tuple[str, ...]

    def floor(self) -> SemVer:
        return SemVer(self.major or 0, self.minor or 0, self.patch or 0, self.prerelease)


def _partial(text: str) -> _Partial | None:
    match = _PARTIAL_RE.match(text)
    if match is None:
        return None

    def number(name: str) -> int | None:
        value = match.group(name)
        return None if value is None or value in {"x", "X", "*"} else int(value)

    major, minor, patch = number("major"), number("minor"), number("patch")
    # "1.x.3" is treated as "1.x": everything after a wildcard is a wildcard.
    if major is None:
        minor = patch = None
    elif minor is None:
        patch = None
    pre = match.group("pre")
    return _Partial(major, minor, patch, tuple(pre.split(".")) if pre and patch is not None else ())


def _upper(major: int, minor: int = 0, patch: int = 0) -> SemVer:
    """Exclusive upper bound that also excludes the prereleases of that release (``X-0``)."""
    return SemVer(major, minor, patch, ("0",))


def _x_range(p: _Partial) -> ComparatorSet:
    if p.major is None:
        return _ANY
    if p.minor is None:
        return (Comparator(">=", p.floor()), Comparator("<", _upper(p.major + 1)))
    if p.patch is None:
        return (Comparator(">=", p.floor()), Comparator("<", _upper(p.major, p.minor + 1)))
    return (Comparator("=", p.floor()),)


def _tilde(p: _Partial) -> ComparatorSet:
    if p.major is None:
        return _ANY
    if p.minor is None:
        return (Comparator(">=", p.floor()), Comparator("<", _upper(p.major + 1)))
    return (Comparator(">=", p.floor()), Comparator("<", _upper(p.major, p.minor + 1)))


def _caret(p: _Partial) -> ComparatorSet:
    if p.major is None:
        return _ANY
    low = Comparator(">=", p.floor())
    if p.minor is None:
        return (low, Comparator("<", _upper(p.major + 1)))
    if p.major > 0:
        return (low, Comparator("<", _upper(p.major + 1)))
    if p.patch is None or p.minor > 0:
        # ^0.2.3 / ^0.2 -> <0.3.0 ; ^0.0 / ^0.0.x -> <0.1.0
        return (low, Comparator("<", _upper(0, p.minor + 1)))
    return (low, Comparator("<", _upper(0, 0, p.patch + 1)))


_OPS: dict[str, Op] = {"<": "<", "<=": "<=", ">": ">", ">=": ">="}


def _comparison(op: Op, p: _Partial) -> ComparatorSet | None:
    if p.major is None:
        # ">*" and "<*" match nothing; ">=*" / "<=*" match anything.
        return _ANY if op in {">=", "<="} else None
    if p.patch is not None:
        return (Comparator(op, p.floor()),)
    # Partial version: round to the range the partial denotes.
    if op == ">=":
        return (Comparator(">=", p.floor()),)
    if op == "<":
        return (Comparator("<", _upper(p.major, p.minor or 0)),)
    nxt = _upper(p.major + 1) if p.minor is None else _upper(p.major, p.minor + 1)
    if op == ">":
        return (Comparator(">=", SemVer(*nxt.release)),)
    return (Comparator("<", nxt),)  # "<="


def _parse_comparator(token: str) -> ComparatorSet | None:
    """One whitespace-free token, e.g. ``^1.2.3``, ``>=2``, ``1.x``; None when invalid."""
    for prefix in (">=", "<=", ">", "<", "=", "^", "~>", "~"):
        if token.startswith(prefix):
            op, rest = prefix, token[len(prefix) :]
            break
    else:
        op, rest = "", token
    part = _partial(rest)
    if part is None:
        return None
    if op in {"", "="}:
        return _x_range(part)
    if op == "^":
        return _caret(part)
    if op in {"~", "~>"}:
        return _tilde(part)
    return _comparison(_OPS[op], part)


def _hyphen(low_text: str, high_text: str) -> ComparatorSet | None:
    low, high = _partial(low_text), _partial(high_text)
    if low is None or high is None:
        return None
    lower = () if low.major is None else (Comparator(">=", low.floor()),)
    if high.major is None:
        upper: ComparatorSet = ()
    elif high.minor is None:
        upper = (Comparator("<", _upper(high.major + 1)),)
    elif high.patch is None:
        upper = (Comparator("<", _upper(high.major, high.minor + 1)),)
    else:
        upper = (Comparator("<=", high.floor()),)
    return (*lower, *upper) or _ANY


def parse_range(spec: str) -> list[ComparatorSet] | None:
    """The ``||``-separated comparator sets of an npm range, or None when it is not a range."""
    if len(spec) > MAX_RANGE_CHARS:
        return None
    sets: list[ComparatorSet] = []
    for alternative in spec.split("||"):
        text = alternative.strip()
        if not text:
            sets.append(_ANY)
            continue
        if hyphen := _HYPHEN_RE.match(text):
            parsed = _hyphen(hyphen.group(1), hyphen.group(2))
            if parsed is None:
                return None
            sets.append(parsed)
            continue
        comparators: list[Comparator] = []
        for token in _OPERATOR_RE.sub(r"\1", text).split():
            parsed = _parse_comparator(token)
            if parsed is None:
                return None
            comparators.extend(parsed)
        sets.append(tuple(comparators))
    return sets


def _set_allows(comparators: ComparatorSet, v: SemVer) -> bool:
    if not all(c.test(v) for c in comparators):
        return False
    if not v.is_prerelease:
        return True
    return any(c.version.is_prerelease and c.version.release == v.release for c in comparators)


def satisfies(version: str, spec: str) -> bool:
    """True when ``version`` is inside the npm range ``spec`` (False for invalid input)."""
    v = parse(version)
    sets = parse_range(spec)
    if v is None or sets is None:
        return False
    return any(_set_allows(s, v) for s in sets)


def max_satisfying(versions: list[str], spec: str) -> str | None:
    """Highest version in ``versions`` that satisfies ``spec`` (what npm resolves to)."""
    sets = parse_range(spec)
    if sets is None:
        return None
    best: tuple[SemVer, str] | None = None
    for text in versions:
        v = parse(text)
        if v is None or not any(_set_allows(s, v) for s in sets):
            continue
        if best is None or v > best[0]:
            best = (v, text)
    return best[1] if best else None


def sort_versions(versions: list[str]) -> list[str]:
    """Parseable versions in ascending order (unparseable ones are dropped)."""
    parsed = [(v, text) for text in versions if (v := parse(text)) is not None]
    return [text for _, text in sorted(parsed, key=lambda item: item[0])]


def rewrite_spec(spec: str, version: str) -> str:
    """A manifest spec pointing at ``version`` in the style of ``spec``.

    ``^0.6.11`` -> ``^0.6.12``, ``~1.2.3`` -> ``~1.2.4``, ``0.4.0`` -> ``4.2.2`` (exact stays
    exact). Anything more complex (``>=1 <2``, ``1.x``, tags) becomes the exact version, so the
    result never admits an unverified version.
    """
    match = _SIMPLE_SPEC_RE.match(spec.strip())
    if match is None or parse(match.group("version")) is None:
        return version
    prefix = match.group("prefix") or ""
    if prefix == "v":
        prefix = ""
    return f"{prefix}{version}"

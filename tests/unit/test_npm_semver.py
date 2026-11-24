import itertools
import random

import pytest

from guardian.remediation.npm_semver import (
    SemVer,
    compare,
    jump,
    max_satisfying,
    parse,
    parse_range,
    rewrite_spec,
    satisfies,
    sort_versions,
)


def test_parse_full_versions():
    assert parse("1.2.3") == SemVer(1, 2, 3)
    assert parse("v1.2.3") == SemVer(1, 2, 3)
    assert parse("=1.2.3") == SemVer(1, 2, 3)
    assert parse("1.2.3-beta.2+build.7") == SemVer(1, 2, 3, ("beta", "2"))
    assert str(parse("1.2.3-rc.1")) == "1.2.3-rc.1"
    for bad in ("1.2", "x", "", "1.2.3.4", "latest", "1.2.3-"):
        assert parse(bad) is None


def test_precedence_matches_the_semver_spec_example():
    ordered = [
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-alpha.beta",
        "1.0.0-beta",
        "1.0.0-beta.2",
        "1.0.0-beta.11",
        "1.0.0-rc.1",
        "1.0.0",
        "1.0.1",
        "1.1.0",
        "2.0.0",
    ]
    for a, b in itertools.pairwise(ordered):
        assert compare(a, b) == -1
        assert compare(b, a) == 1
    assert compare("1.0.0", "1.0.0+build") == 0
    shuffled = ordered[:]
    random.Random(7).shuffle(shuffled)  # noqa: S311 - reproducible test data
    assert sort_versions([*shuffled, "not-a-version"]) == ordered


def test_compare_rejects_garbage():
    with pytest.raises(ValueError, match="Not a semantic version"):
        compare("1.0.0", "nope")


@pytest.mark.parametrize(
    ("spec", "inside", "outside"),
    [
        ("1.2.3", ["1.2.3"], ["1.2.4", "1.2.2"]),
        ("=1.2.3", ["1.2.3"], ["1.2.4"]),
        ("^1.2.3", ["1.2.3", "1.9.9"], ["1.2.2", "2.0.0", "2.0.0-0"]),
        ("^0.6.11", ["0.6.11", "0.6.99"], ["0.7.0", "0.6.10"]),
        ("^0.0.3", ["0.0.3"], ["0.0.4", "0.0.2"]),
        ("^0.0", ["0.0.0", "0.0.9"], ["0.1.0"]),
        ("^1.x", ["1.0.0", "1.9.0"], ["2.0.0"]),
        ("^0.x", ["0.0.1", "0.9.0"], ["1.0.0"]),
        ("~1.2.3", ["1.2.3", "1.2.9"], ["1.3.0", "1.2.2"]),
        ("~1.2", ["1.2.0", "1.2.9"], ["1.3.0"]),
        ("~1", ["1.0.0", "1.9.9"], ["2.0.0"]),
        ("~0.2.3", ["0.2.3", "0.2.9"], ["0.3.0"]),
        (">1.2.3", ["1.2.4", "9.0.0"], ["1.2.3"]),
        (">=1.2.3", ["1.2.3"], ["1.2.2"]),
        ("<1.2.3", ["1.2.2", "0.0.1"], ["1.2.3"]),
        ("<=1.2.3", ["1.2.3"], ["1.2.4"]),
        (">1.1", ["1.2.0"], ["1.1.9"]),
        ("<=1.1", ["1.1.9"], ["1.2.0"]),
        ("<1.2", ["1.1.9"], ["1.2.0"]),
        (">=1.2", ["1.2.0"], ["1.1.9"]),
        ("1.x", ["1.0.0", "1.9.9"], ["2.0.0", "0.9.0"]),
        ("1.2.*", ["1.2.0", "1.2.9"], ["1.3.0"]),
        ("1", ["1.0.0", "1.5.0"], ["2.0.0"]),
        ("*", ["0.0.0", "99.0.0"], []),
        ("", ["1.0.0"], []),
        ("1.2.3 - 2.3.4", ["1.2.3", "2.3.4"], ["1.2.2", "2.3.5"]),
        ("1.2 - 2.3", ["1.2.0", "2.3.9"], ["2.4.0"]),
        ("1.2.3 - 2", ["2.9.9"], ["3.0.0"]),
        ("<2 || >=3", ["1.0.0", "3.1.0"], ["2.5.0"]),
        (">= 1.2.3 < 2", ["1.2.3", "1.9.0"], ["2.0.0"]),
        (">=1.0.0 <1.5.0 || 2.x", ["1.4.0", "2.1.0"], ["1.5.0", "3.0.0"]),
        ("^1.2.3-beta.2", ["1.2.3-beta.2", "1.2.3-beta.10", "1.2.3", "1.9.0"], ["1.2.4-beta.1"]),
    ],
)
def test_satisfies(spec, inside, outside):
    for version in inside:
        assert satisfies(version, spec), f"{version} should satisfy {spec!r}"
    for version in outside:
        assert not satisfies(version, spec), f"{version} should not satisfy {spec!r}"


def test_prereleases_need_an_opt_in_comparator():
    assert not satisfies("2.0.0-beta.1", ">=1.0.0")
    assert satisfies("2.0.0-beta.1", ">=2.0.0-alpha")
    assert not satisfies("2.0.1-beta.1", ">=2.0.0-alpha")


def test_non_ranges_never_satisfy():
    for spec in ("latest", "github:user/repo", "file:../x", "https://x/y.tgz", "^", "a.b.c"):
        assert parse_range(spec) is None
        assert not satisfies("1.0.0", spec)
    assert not satisfies("garbage", "^1.0.0")
    assert parse_range("x" * 5000) is None
    assert not satisfies("1.0.0", ">*")


def test_property_caret_equals_explicit_bounds():
    rng = random.Random(42)  # noqa: S311 - reproducible test data
    for _ in range(300):
        base = SemVer(rng.randint(0, 3), rng.randint(0, 3), rng.randint(0, 3))
        probe = f"{rng.randint(0, 4)}.{rng.randint(0, 4)}.{rng.randint(0, 4)}"
        if base.major > 0:
            upper = f"{base.major + 1}.0.0-0"
        elif base.minor > 0:
            upper = f"0.{base.minor + 1}.0-0"
        else:
            upper = f"0.0.{base.patch + 1}-0"
        assert satisfies(probe, f"^{base}") == satisfies(probe, f">={base} <{upper}")
        # ~ is never wider than ^ for versions >= 1.0.0
        if base.major > 0 and satisfies(probe, f"~{base}"):
            assert satisfies(probe, f"^{base}")


def test_property_or_is_union_and_space_is_intersection():
    rng = random.Random(3)  # noqa: S311 - reproducible test data
    specs = ["^1.2.0", "~2.0.1", "<1.5.0", ">=0.9.0", "1.x", "2.0.0 - 2.1.0"]
    for _ in range(200):
        a, b = rng.sample(specs, 2)
        v = f"{rng.randint(0, 3)}.{rng.randint(0, 3)}.{rng.randint(0, 3)}"
        assert satisfies(v, f"{a} || {b}") == (satisfies(v, a) or satisfies(v, b))
        if " - " not in a and " - " not in b:
            assert satisfies(v, f"{a} {b}") == (satisfies(v, a) and satisfies(v, b))


def test_max_satisfying_is_what_npm_resolves():
    versions = ["6.9.6", "6.9.7", "6.10.0", "7.0.0-rc.1", "junk"]
    assert max_satisfying(versions, "~6.9.0") == "6.9.7"
    assert max_satisfying(versions, "^6.9.0") == "6.10.0"
    assert max_satisfying(versions, "^8") is None
    assert max_satisfying(versions, "latest") is None


def test_jump():
    assert jump("0.4.0", "4.2.2") == "major"
    assert jump("2.18.0", "2.19.3") == "minor"
    assert jump("1.4.2", "1.4.3") == "patch"
    assert jump("1.4.2", "nope") is None


def test_rewrite_spec_keeps_the_operator_style():
    assert rewrite_spec("^0.6.11", "0.6.12") == "^0.6.12"
    assert rewrite_spec("~1.0.0", "1.0.1") == "~1.0.1"
    assert rewrite_spec("0.4.0", "4.2.2") == "4.2.2"
    assert rewrite_spec(">=1.2.0", "1.3.0") == ">=1.3.0"
    assert rewrite_spec("v1.2.0", "1.3.0") == "1.3.0"
    assert rewrite_spec(">=1 <2", "1.5.0") == "1.5.0"
    assert rewrite_spec("latest", "1.5.0") == "1.5.0"

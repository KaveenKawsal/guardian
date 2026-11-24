# ruff: noqa: RUF001, S105 - U+2139 is real node reporter output; SPEC_PASS is not a secret
from remediation_fakes import sbom_with, vuln

from guardian.core.models import Component, Sbom
from guardian.core.remediation_models import ComponentChange
from guardian.remediation.diff import diff_findings, diff_sboms, split_purl
from guardian.remediation.testparse import (
    TestSummary,
    is_known_conflict,
    parse_node_test_output,
)

SPEC_PASS = """\
\x1b[32m✔ insecurity › hashes passwords (1.2ms)\x1b[39m
ℹ tests 214
ℹ suites 31
ℹ pass 214
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ duration_ms 5123.4
"""

SPEC_RSN_FAIL = """\
✖ rsn › verdicts match the challenge snippets (12.3ms)
ℹ tests 214
ℹ pass 212
ℹ fail 2

✖ failing tests:

test at test/server/rsn.unit.test.ts:42:3
✖ rsn › verdicts match the challenge snippets (12.3ms)
  AssertionError [ERR_ASSERTION]: ...

test at /work/test/server/rsn.unit.test.ts:77:5
✖ rsn › second check (1ms)
"""

SPEC_REAL_FAIL = (
    SPEC_RSN_FAIL
    + """
test at ./test/server/insecurity.unit.test.ts:10:3
✖ insecurity › verifies jwt (3ms)
"""
)

TAP = """\
TAP version 13
not ok 1 - test/server/verify.unit.test.ts
  ---
  location: '/work/test/server/verify.unit.test.ts:1:1'
  ...
ok 2 - test/server/utils.unit.test.ts
1..2
# tests 30
# suites 2
# pass 29
# fail 1
"""


def test_spec_reporter_counts():
    summary = parse_node_test_output(SPEC_PASS)
    assert summary == TestSummary(discovered=214, passed=214, failed=0, failing_files=())
    assert not is_known_conflict(summary)


def test_rsn_only_failures_are_known_conflicts():
    summary = parse_node_test_output(SPEC_RSN_FAIL)
    assert (summary.discovered, summary.passed, summary.failed) == (214, 212, 2)
    assert summary.failing_files == ("test/server/rsn.unit.test.ts",)
    assert is_known_conflict(summary)


def test_real_failures_are_not_known_conflicts():
    summary = parse_node_test_output(SPEC_REAL_FAIL)
    assert summary.failing_files == (
        "test/server/insecurity.unit.test.ts",
        "test/server/rsn.unit.test.ts",
    )
    assert not is_known_conflict(summary)


def test_tap_reporter():
    summary = parse_node_test_output(TAP)
    assert (summary.discovered, summary.passed, summary.failed) == (30, 29, 1)
    assert summary.failing_files == ("test/server/verify.unit.test.ts",)


def test_host_paths_are_relativized_and_unknown_output():
    text = "test at /tmp/x/src/test/server/a.unit.test.ts:1:1\n# fail 1\n"
    summary = parse_node_test_output(text, roots=("/tmp/x/src",))
    assert summary.failing_files == ("test/server/a.unit.test.ts",)
    assert parse_node_test_output("garbage") == TestSummary()
    assert not is_known_conflict(TestSummary(failed=1))


# --- diff ---------------------------------------------------------------------------------


def test_split_purl():
    assert split_purl("pkg:npm/%40angular/core@17.0.0?x=1#sub") == (
        "pkg:npm/%40angular/core",
        "17.0.0",
    )
    assert split_purl("pkg:npm/lodash") == ("pkg:npm/lodash", None)


def test_diff_sboms_added_removed_changed():
    before = sbom_with("pkg:npm/lodash@4.17.20", "pkg:npm/old@1.0.0", "pkg:npm/dup@1.0.0")
    after = sbom_with(
        "pkg:npm/lodash@4.17.21",
        "pkg:npm/new@2.0.0",
        "pkg:npm/dup@1.0.0",
        "pkg:npm/dup@2.0.0",
    )
    diff = diff_sboms(before, after)
    assert diff.changed == [
        ComponentChange(purl_base="pkg:npm/lodash", from_version="4.17.20", to_version="4.17.21")
    ]
    assert diff.added == ["pkg:npm/dup@2.0.0", "pkg:npm/new@2.0.0"]
    assert diff.removed == ["pkg:npm/old@1.0.0"]


def test_diff_sboms_handles_missing_sides_and_purl_less_components():
    assert diff_sboms(None, None).added == []
    after = Sbom(
        spec_version="1.5",
        generator="t",
        components=[
            Component(ref="a", name="thing", group="acme", version="1.0", purl_type="generic"),
            Component(ref="b", name="bare"),
        ],
    )
    diff = diff_sboms(None, after)
    assert diff.added == ["component:bare", "generic:acme/thing@1.0"]
    assert diff_sboms(after, None).removed == diff.added


def test_diff_findings_by_id():
    resolved, still, new = diff_findings([vuln("a"), vuln("b")], [vuln("b"), vuln("c")])
    assert (resolved, still, new) == (["a"], ["b"], ["c"])

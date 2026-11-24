import pytest
from juice_shop import FakeRegistry, build_world

from guardian.core.remediation_models import RemediationActionType as A
from guardian.core.remediation_models import SemverJump
from guardian.remediation.candidates import (
    find_dependency,
    generate_candidates,
    npm_purl,
    read_manifest,
    semver_jump,
)


@pytest.fixture
def world(tmp_path):
    return build_world(tmp_path / "juice-shop")


def candidates_for(world, name, registry=None, **kwargs):
    return generate_candidates(
        world.case(name),
        world.package_findings(name),
        world.sbom,
        world.graph,
        kwargs.pop("index", world.index),
        world.assessments,
        registry if registry is not None else FakeRegistry(),
        world.root,
        **kwargs,
    )


def by_action(candidates, action):
    return [c for c in candidates if c.action_type is action]


def test_jsonwebtoken_major_upgrades(world):
    found = candidates_for(world, "jsonwebtoken")
    upgrades = by_action(found, A.UPGRADE)
    assert [c.to_version for c in upgrades] == ["9.0.0", "4.2.2"]
    full, partial = upgrades
    case_ids = set(world.case("jsonwebtoken").finding_ids)
    assert len(case_ids) == 3
    assert set(full.fixes_finding_ids) == case_ids
    assert full.semver_jump is SemverJump.MAJOR
    assert full.version_verified is True
    assert full.strategy == "direct"
    assert full.from_version == "0.4.0"
    assert full.manifest_path == "package.json"
    assert (
        "major version jump 0.x → 9.x for jsonwebtoken: breaking changes expected per semver"
        in full.compatibility_notes
    )
    assert any('"jsonwebtoken": "0.4.0" → "9.0.0"' in n for n in full.compatibility_notes)
    assert "registry: jsonwebtoken 9.0.0 published, not deprecated" in full.evidence
    assert "advisory:CVE-2015-9235" in full.evidence
    assert all(f"finding:{i}" in full.evidence for i in case_ids)
    # 4.2.2 fixes only the verification bypass; the others stay.
    assert len(partial.fixes_finding_ids) == 1
    assert partial.semver_jump is SemverJump.MAJOR
    assert any("partial fix" in n and "CVE-2022-23539" in n for n in partial.compatibility_notes)
    # Prereleases (10.0.0-beta.1) are never candidates.
    assert all("beta" not in (c.to_version or "") for c in found)


def test_rollback_text_is_exact(world):
    case = world.case("jsonwebtoken")
    full = by_action(candidates_for(world, "jsonwebtoken", worktree_root="/wt"), A.UPGRADE)[0]
    assert full.rollback == (
        f"git worktree remove /wt/{case.id} && git branch -D guardian/fix-{case.id}; "
        'or restore "jsonwebtoken": "0.4.0" in package.json'
    )


def test_expected_risk_reduction(world):
    full, partial = by_action(candidates_for(world, "jsonwebtoken"), A.UPGRADE)
    scores = sorted(
        (world.assessments[f.id].score for f in world.package_findings("jsonwebtoken")),
        reverse=True,
    )
    assert full.expected_risk_reduction == round(scores[0], 1)  # all fixed: full max score
    assert partial.expected_risk_reduction == round(scores[0] - scores[1], 1)
    for c in candidates_for(world, "jsonwebtoken"):
        if c.action_type in {A.BLOCK, A.ESCALATE}:
            assert c.expected_risk_reduction is None


def test_deprecated_versions_are_skipped(world):
    (upgrade,) = by_action(candidates_for(world, "express-jwt"), A.UPGRADE)
    assert upgrade.to_version == "6.1.0"  # 6.0.0 is deprecated


def test_exact_pin_patch_and_caret_ranges(world):
    (sanitize,) = by_action(candidates_for(world, "sanitize-html"), A.UPGRADE)
    assert sanitize.to_version == "1.4.3"
    assert sanitize.semver_jump is SemverJump.PATCH
    assert any('"1.4.2" → "1.4.3"' in n for n in sanitize.compatibility_notes)
    (mars,) = by_action(candidates_for(world, "marsdb"), A.UPGRADE)
    assert any('"^0.6.11" → "^0.6.12"' in n for n in mars.compatibility_notes)
    (moment,) = by_action(candidates_for(world, "moment"), A.UPGRADE)
    assert moment.to_version == "2.19.3"
    assert moment.semver_jump is SemverJump.MINOR
    assert any('"^2.18.0" → "^2.19.3"' in n for n in moment.compatibility_notes)


def test_transitive_gets_parent_and_override(world):
    found = candidates_for(world, "qs")
    parent = next(c for c in found if c.strategy == "parent")
    assert parent.action_type is A.UPGRADE
    assert parent.target_package == "express"
    assert (parent.from_version, parent.to_version) == ("4.17.1", "4.17.3")
    assert parent.component == "pkg:npm/qs@6.7.0"
    assert any("resolves to qs 6.9.7" in n for n in parent.compatibility_notes)
    assert parent.fixes_finding_ids == world.case("qs").finding_ids
    override = next(c for c in found if c.strategy == "override")
    assert override.action_type is A.PIN
    assert override.to_version == "6.7.3"
    assert any("outside that range" in n for n in override.compatibility_notes)
    assert override.rollback.endswith('remove "qs" from "overrides" in package.json')
    assert not by_action(found, A.REMOVE)  # never remove a transitive package


def test_unused_direct_dependency_can_be_removed(world):
    found = candidates_for(world, "unused-lib")
    (remove,) = by_action(found, A.REMOVE)
    assert remove.fixes_finding_ids == world.case("unused-lib").finding_ids
    assert "unused-lib is not referenced in package.json scripts" in remove.compatibility_notes
    assert remove.to_version is None
    # imported packages are never offered for removal
    assert not by_action(candidates_for(world, "jsonwebtoken"), A.REMOVE)


def test_no_remove_without_code_index_or_when_used_by_scripts(world):
    assert not by_action(candidates_for(world, "unused-lib", index=None), A.REMOVE)
    manifest = (world.root / "package.json").read_text()
    (world.root / "package.json").write_text(
        manifest.replace('"mocha test/server"', '"unused-lib --check && mocha"')
    )
    assert not by_action(candidates_for(world, "unused-lib"), A.REMOVE)


def test_block_and_escalate_always_last(world):
    for name in ("jsonwebtoken", "qs", "unused-lib", "sanitize-html"):
        found = candidates_for(world, name)
        assert [c.action_type for c in found[-2:]] == [A.BLOCK, A.ESCALATE]
        assert found[-2].fixes_finding_ids == []
        assert found[-1].rollback == "no change to revert"


def test_registry_down_falls_back_to_osv_versions(world):
    found = candidates_for(world, "jsonwebtoken", registry=FakeRegistry(down=True))
    upgrades = by_action(found, A.UPGRADE)
    assert [c.to_version for c in upgrades] == ["9.0.0", "4.2.2"]
    assert all(c.version_verified is False for c in upgrades)
    assert all(
        "no registry verification: version taken from OSV fixed versions" in c.compatibility_notes
        for c in upgrades
    )
    assert all(not any(e.startswith("registry:") for e in c.evidence) for c in upgrades)
    qs = candidates_for(world, "qs", registry=FakeRegistry(down=True))
    assert not [c for c in qs if c.strategy == "parent"]  # cannot verify parent ranges
    (override,) = [c for c in qs if c.strategy == "override"]
    assert override.version_verified is False
    assert override.to_version == "6.7.3"


def test_ids_are_deterministic(world):
    first = [c.id for c in candidates_for(world, "jsonwebtoken")]
    assert first == [c.id for c in candidates_for(world, "jsonwebtoken")]
    assert len(set(first)) == len(first)


def test_no_vulnerability_findings_only_escalates(world):
    (only,) = generate_candidates(
        world.case("jsonwebtoken"), [], world.sbom, world.graph, None, {}, None, world.root
    )
    assert only.action_type is A.ESCALATE


def test_helpers(world, tmp_path):
    assert npm_purl("@angular/core", "1.0.0") == "pkg:npm/%40angular/core@1.0.0"
    assert npm_purl("qs") == "pkg:npm/qs"
    assert semver_jump(None, "1.0.0") is SemverJump.UNKNOWN
    assert semver_jump("x", "1.0.0") is SemverJump.UNKNOWN
    manifest = read_manifest(world.root)
    assert find_dependency(manifest, "marsdb") == ("dependencies", "^0.6.11")
    assert find_dependency(manifest, "nope") is None
    assert read_manifest(tmp_path / "missing") is None
    (tmp_path / "list").mkdir()
    (tmp_path / "list" / "package.json").write_text("[1]")
    assert read_manifest(tmp_path / "list") is None
    link = tmp_path / "link"
    link.mkdir()
    (link / "package.json").symlink_to(world.root / "package.json")
    assert read_manifest(link) is None

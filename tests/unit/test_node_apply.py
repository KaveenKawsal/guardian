import json

import pytest
from juice_shop import PACKAGE_JSON, FakeRegistry, build_world, manifest

from guardian.adapters.node import NodeAdapter, apply_candidate, npm_name
from guardian.core.exceptions import ApplyError, GuardianError
from guardian.core.remediation_models import RemediationActionType as A
from guardian.core.remediation_models import RemediationCandidate
from guardian.remediation.candidates import generate_candidates


@pytest.fixture
def world(tmp_path):
    return build_world(tmp_path / "juice-shop")


def candidates(world, name):
    return generate_candidates(
        world.case(name),
        world.package_findings(name),
        world.sbom,
        world.graph,
        world.index,
        world.assessments,
        FakeRegistry(),
        world.root,
    )


def pick(world, name, *, action=A.UPGRADE, strategy=None, to=None):
    return next(
        c
        for c in candidates(world, name)
        if c.action_type is action
        and (strategy is None or c.strategy == strategy)
        and (to is None or c.to_version == to)
    )


def candidate(**kwargs):
    base = {
        "id": "cand_x",
        "case_id": "rc_x",
        "action_type": A.UPGRADE,
        "component": "pkg:npm/jsonwebtoken@0.4.0",
        "to_version": "9.0.0",
        "rollback": "-",
        "strategy": "direct",
    }
    return RemediationCandidate(**{**base, **kwargs})


def test_direct_upgrade_preserves_formatting(world):
    changed = apply_candidate(world.root, pick(world, "jsonwebtoken", to="9.0.0"))
    assert changed == ["package.json"]
    text = (world.root / "package.json").read_text()
    assert text == PACKAGE_JSON.replace('"jsonwebtoken": "0.4.0"', '"jsonwebtoken": "9.0.0"')


def test_caret_range_keeps_its_operator(world):
    apply_candidate(world.root, pick(world, "marsdb"))
    assert manifest(world.root)["dependencies"]["marsdb"] == "^0.6.12"


def test_parent_strategy_edits_the_parent(world):
    apply_candidate(world.root, pick(world, "qs", strategy="parent"))
    deps = manifest(world.root)["dependencies"]
    assert deps["express"] == "^4.17.3"
    assert "qs" not in deps


def test_override_adds_an_overrides_object_at_the_end(world):
    apply_candidate(world.root, pick(world, "qs", action=A.PIN, strategy="override"))
    data = manifest(world.root)
    assert data["overrides"] == {"qs": "6.7.3"}
    assert list(data) == ["name", "version", "scripts", "dependencies", "overrides"]
    text = (world.root / "package.json").read_text()
    assert text.endswith('  "overrides": {\n    "qs": "6.7.3"\n  }\n}\n')


def test_remove(world):
    apply_candidate(world.root, pick(world, "unused-lib", action=A.REMOVE))
    assert "unused-lib" not in manifest(world.root)["dependencies"]


def test_tabs_crlf_and_no_trailing_newline_survive(tmp_path):
    text = '{\r\n\t"dependencies": {\r\n\t\t"jsonwebtoken": "0.4.0",\r\n\t\t"zz": "1"\r\n\t}\r\n}'
    (tmp_path / "package.json").write_text(text, newline="")
    apply_candidate(tmp_path, candidate())
    out = (tmp_path / "package.json").read_bytes().decode()
    assert out == text.replace("0.4.0", "9.0.0")


def test_four_space_indent_and_dev_dependencies(tmp_path):
    data = {"devDependencies": {"jsonwebtoken": "~0.4.0"}}
    (tmp_path / "package.json").write_text(json.dumps(data, indent=4) + "\n")
    apply_candidate(tmp_path, candidate())
    assert (tmp_path / "package.json").read_text() == (
        json.dumps({"devDependencies": {"jsonwebtoken": "~9.0.0"}}, indent=4) + "\n"
    )


def test_no_change_returns_nothing(tmp_path):
    (tmp_path / "package.json").write_text(
        '{\n  "dependencies": {\n    "jsonwebtoken": "9.0.0"\n  }\n}\n'
    )
    assert apply_candidate(tmp_path, candidate()) == []


def test_symlinked_manifest_is_refused(world, tmp_path):
    other = tmp_path / "elsewhere"
    other.mkdir()
    (other / "package.json").write_text(PACKAGE_JSON)
    (world.root / "package.json").unlink()
    (world.root / "package.json").symlink_to(other / "package.json")
    with pytest.raises(ApplyError, match="symlink"):
        apply_candidate(world.root, pick(world, "marsdb"))
    assert (other / "package.json").read_text() == PACKAGE_JSON


def test_symlinked_directory_is_refused(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "package.json").write_text('{"dependencies": {"jsonwebtoken": "0.4.0"}}')
    wt = tmp_path / "wt"
    wt.mkdir()
    (wt / "sub").symlink_to(real, target_is_directory=True)
    with pytest.raises(ApplyError, match="symlink"):
        apply_candidate(wt, candidate(manifest_path="sub/package.json"))


@pytest.mark.parametrize(
    "path", ["../package.json", "/etc/package.json", "sub/../../package.json", "pom.xml", ""]
)
def test_escaping_or_odd_manifest_paths_are_refused(tmp_path, path):
    with pytest.raises(ApplyError):
        apply_candidate(tmp_path, candidate(manifest_path=path or "."))


@pytest.mark.parametrize("action", [A.BLOCK, A.ESCALATE])
def test_non_code_actions_raise(world, action):
    with pytest.raises(GuardianError, match="non-code"):
        apply_candidate(world.root, pick(world, "jsonwebtoken", action=action))
    assert (world.root / "package.json").read_text() == PACKAGE_JSON


def test_other_failures(tmp_path):
    with pytest.raises(ApplyError, match="does not exist"):
        apply_candidate(tmp_path, candidate())
    (tmp_path / "package.json").write_text("{nope")
    with pytest.raises(ApplyError, match="not valid JSON"):
        apply_candidate(tmp_path, candidate())
    (tmp_path / "package.json").write_text("[]")
    with pytest.raises(ApplyError, match="not a JSON object"):
        apply_candidate(tmp_path, candidate())
    (tmp_path / "package.json").write_text('{"dependencies": {}, "overrides": []}')
    with pytest.raises(ApplyError, match="not declared"):
        apply_candidate(tmp_path, candidate())
    with pytest.raises(ApplyError, match="not an object"):
        apply_candidate(tmp_path, candidate(strategy="override"))
    with pytest.raises(ApplyError, match="not an npm package"):
        apply_candidate(tmp_path, candidate(component="pkg:pypi/x@1"))
    with pytest.raises(ApplyError, match="target_package"):
        apply_candidate(tmp_path, candidate(strategy="parent"))
    (tmp_path / "package.json").write_text('{"dependencies": {"jsonwebtoken": "1"}}')
    with pytest.raises(ApplyError, match="needs a target version"):
        apply_candidate(tmp_path, candidate(to_version=None))
    with pytest.raises(ApplyError, match="not supported"):
        apply_candidate(tmp_path, candidate(action_type=A.REPLACE))


def test_adapter_method_and_npm_name(world):
    assert NodeAdapter().apply_candidate(world.root, pick(world, "marsdb")) == ["package.json"]
    assert npm_name("pkg:npm/%40angular/core@1.0.0") == "@angular/core"
    assert npm_name("not a purl") is None

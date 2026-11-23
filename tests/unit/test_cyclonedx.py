from pathlib import Path

import pytest

from guardian.analysis.cyclonedx import SbomParseError, normalize_source_path, parse_cyclonedx
from guardian.core.models import DependencyScope, DirectSource, Ecosystem

FIXTURES = Path(__file__).parents[1] / "fixtures" / "sbom"
ROOT = Path("C:/repo") if Path.cwd().drive else Path("/repo")


def _parse(name, manifests=frozenset(), declared=None):
    return parse_cyclonedx(
        (FIXTURES / name).read_bytes(),
        repo_root=ROOT,
        manifests=set(manifests),
        declared=declared,
    )


def _by_name(sbom):
    return {c.name: c for c in sbom.components}


class TestNodeSbom:
    def test_root_edges_identify_direct_dependencies(self):
        sbom = _parse("node-express.cdx.json")
        assert sbom.direct_source is DirectSource.SBOM
        assert sbom.generator == "cdxgen 12.9.3"
        assert sorted(c.name for c in sbom.direct_components) == ["express", "lodash"]
        assert _by_name(sbom)["accepts"].direct is False

    def test_component_normalization(self):
        components = _by_name(_parse("node-express.cdx.json"))
        express = components["express"]
        assert express.ecosystem is Ecosystem.NODE
        assert express.purl_type == "npm"
        assert express.group is None  # empty string normalized away
        assert express.licenses == ["MIT"]
        assert components["accepts"].licenses == ["MIT OR Apache-2.0"]
        assert components["node"].display_name == "@types/node@20.0.0"
        assert components["node"].scope is DependencyScope.OPTIONAL
        assert components["lodash"].scope is DependencyScope.REQUIRED

    def test_nested_components_are_flattened(self):
        nested = _by_name(_parse("node-express.cdx.json"))["lodash-nested-plugin"]
        assert nested.ref == "nested-ref"
        assert nested.ecosystem is None

    def test_root_component_is_not_a_dependency(self):
        assert "sample" not in _by_name(_parse("node-express.cdx.json"))

    def test_dangling_references_are_dropped_with_warning(self):
        sbom = _parse("node-express.cdx.json")
        assert all("ghost" not in e.target for e in sbom.edges)
        assert any("unknown components" in w for w in sbom.warnings)

    def test_sbom_and_manifest_union(self):
        sbom = _parse(
            "node-express.cdx.json", declared={Ecosystem.NODE: {"express", "@types/node"}}
        )
        assert sbom.direct_source is DirectSource.SBOM_AND_MANIFEST
        assert sorted(c.display_name for c in sbom.direct_components) == [
            "@types/node@20.0.0",
            "express@4.17.1",
            "lodash@4.17.20",
        ]


class TestPythonSbom:
    def test_manifest_names_identify_direct_dependencies(self):
        sbom = _parse(
            "python-uv.cdx.json",
            manifests={"pyproject.toml"},
            declared={Ecosystem.PYTHON: {"pydantic", "pydantic-settings"}},
        )
        assert sbom.direct_source is DirectSource.MANIFEST
        # pydantic is both direct and transitive (via pydantic-settings): still direct.
        assert sorted(c.name for c in sbom.direct_components) == ["pydantic", "pydantic-settings"]
        assert sbom.generator == "cdxgen 11.0.0"  # CycloneDX 1.4-style tools list
        assert _by_name(sbom)["pydantic"].declared_in == ["pyproject.toml"]
        assert {"app"}.isdisjoint(_by_name(sbom))
        root_edges = {e.target for e in sbom.edges if e.source == sbom.root_ref}
        assert root_edges == {"pkg:pypi/pydantic@2.14.4", "pkg:pypi/pydantic-settings@2.16.3"}

    def test_graph_inference_fallback_is_flagged(self):
        sbom = _parse("python-uv.cdx.json")
        assert sbom.direct_source is DirectSource.GRAPH_INFERENCE
        assert sorted(c.name for c in sbom.direct_components) == ["pydantic-settings", "pytest"]
        assert any("inferred" in w for w in sbom.warnings)


def test_no_graph_leaves_direct_unknown():
    bom = '{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"name": "x"}]}'
    sbom = parse_cyclonedx(bom, repo_root=ROOT, manifests=set())
    assert sbom.direct_source is DirectSource.UNKNOWN
    assert sbom.components[0].direct is None
    assert sbom.components[0].ref == "x@"
    assert sbom.generator == "unknown"


@pytest.mark.parametrize(
    "document",
    ["not json", '{"bomFormat": "SPDX", "specVersion": "2.3"}', '{"bomFormat": "CycloneDX"}'],
)
def test_invalid_documents_raise(document):
    with pytest.raises(SbomParseError):
        parse_cyclonedx(document, repo_root=ROOT, manifests=set())


def test_duplicate_refs_warn():
    bom = (
        '{"bomFormat": "CycloneDX", "specVersion": "1.6", '
        '"components": [{"name": "x", "bom-ref": "a"}, {"name": "y", "bom-ref": "a"}]}'
    )
    sbom = parse_cyclonedx(bom, repo_root=ROOT, manifests=set())
    assert [c.name for c in sbom.components] == ["x"]
    assert sbom.warnings == ["1 duplicate component reference(s) ignored"]


class TestNormalizeSourcePath:
    manifests = frozenset({"package-lock.json", "web/package.json"})

    def test_absolute_inside_root(self, tmp_path):
        value = str(tmp_path / "web" / "package.json")
        assert normalize_source_path(value, tmp_path, set(self.manifests)) == "web/package.json"

    def test_absolute_outside_root(self, tmp_path):
        value = str(tmp_path.parent / "package-lock.json")
        assert normalize_source_path(value, tmp_path, set(self.manifests)) is None

    def test_absolute_inside_root_but_not_a_manifest(self, tmp_path):
        value = str(tmp_path / ".venv" / "METADATA")
        assert normalize_source_path(value, tmp_path, set(self.manifests)) is None

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("package-lock.json", "package-lock.json"),
            ("web\\package.json", "web/package.json"),
            ("Temp\\checkout\\web\\package.json", "web/package.json"),
            ("unrelated.txt", None),
        ],
    )
    def test_relative(self, value, expected, tmp_path):
        assert normalize_source_path(value, tmp_path, set(self.manifests)) == expected

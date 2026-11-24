from pathlib import Path

import pytest

from guardian.analysis.cyclonedx import parse_cyclonedx
from guardian.analysis.osv import is_affected, parse_osv_output
from guardian.core.models import AffectedRange, VulnerabilityDetails

FIXTURES = Path(__file__).parents[1] / "fixtures"


@pytest.fixture(scope="module")
def findings():
    sbom = parse_cyclonedx(
        (FIXTURES / "sbom" / "juice-shop.cdx.json").read_bytes(),
        repo_root=Path("/repo"),
        manifests=set(),
    )
    found, _ = parse_osv_output((FIXTURES / "osv" / "juice-shop.osv.json").read_bytes(), sbom)
    return {f.details.vulnerability_id: f.details for f in found}


def test_ranges_are_captured_from_osv(findings):
    assert findings["CVE-2015-9235"].affected_ranges == [
        AffectedRange(introduced="0", fixed="4.2.2")
    ]
    assert findings["CVE-2022-23539"].affected_ranges == [
        AffectedRange(introduced="0", last_affected="8.5.1")
    ]
    assert len(findings["CVE-2022-24999"].affected_ranges) == 3


def test_is_affected_uses_ranges(findings):
    jwt_bypass = findings["CVE-2015-9235"]
    assert is_affected("0.4.0", jwt_bypass)
    assert is_affected("4.2.1", jwt_bypass)
    assert not is_affected("4.2.2", jwt_bypass)
    legacy_keys = findings["CVE-2022-23539"]
    assert is_affected("8.5.1", legacy_keys)  # last_affected is inclusive
    assert not is_affected("9.0.0", legacy_keys)
    qs = findings["CVE-2022-24999"]
    assert is_affected("6.7.0", qs)
    assert not is_affected("6.7.3", qs)
    assert is_affected("6.9.6", qs)
    assert not is_affected("6.9.7", qs)
    assert not is_affected("6.8.0", qs)  # between ranges
    assert not is_affected("6.6.0", qs)  # before the first introduced


def test_open_ended_and_repeated_introduced():
    from guardian.analysis.osv import (
        OsvPackageInfo,
        OsvVulnerability,
        _affected_ranges,
    )

    vuln = OsvVulnerability.model_validate(
        {
            "id": "X",
            "affected": [
                {"package": {"name": "p"}, "ranges": [{"type": "GIT", "events": []}]},
                {
                    "package": {"name": "p"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "1.0.0"}, {"introduced": "2.0.0"}],
                        }
                    ],
                },
            ],
        }
    )
    ranges = _affected_ranges(OsvPackageInfo(name="p"), [vuln])
    assert ranges == [AffectedRange(introduced="1.0.0"), AffectedRange(introduced="2.0.0")]
    details = VulnerabilityDetails(
        vulnerability_id="X", package="p", ecosystem="npm", affected_ranges=ranges
    )
    assert not is_affected("0.9.0", details)
    assert is_affected("5.0.0", details)


def _legacy(**kwargs):
    return VulnerabilityDetails(vulnerability_id="X", package="p", ecosystem="npm", **kwargs)


def test_fallback_without_ranges_is_conservative():
    d = _legacy(version="0.1.7", fixed_versions=["0.1.10", "1.9.0", "8.0.0"])
    assert is_affected("0.1.7", d)
    assert is_affected("0.1.9", d)
    assert not is_affected("0.1.10", d)  # fixed on its own 0.1 line
    assert is_affected("0.2.0", d)  # no fix known for the 0.2 line
    assert not is_affected("1.9.1", d)
    assert is_affected("2.0.0", d)
    assert not is_affected("8.0.0", d)  # at or above the highest fix
    assert is_affected("3.0.0", _legacy(version="1.0.0"))  # no fix at all
    only_recommended = _legacy(version="4.17.20", recommended_fix="4.17.21")
    assert not is_affected("4.17.21", only_recommended)
    assert is_affected("4.17.20", only_recommended)


def test_old_stored_findings_still_load():
    raw = '{"kind":"vulnerability","vulnerability_id":"X","package":"p","fixed_versions":["1.0.0"]}'
    details = VulnerabilityDetails.model_validate_json(raw)
    assert details.affected_ranges == []

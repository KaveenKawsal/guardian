"""OSV target-version advisory lookups: parsing, host pinning, caching, failures."""

import httpx
import pytest

from guardian.remediation import advisories as adv
from guardian.remediation.advisories import OsvVersionAdvisories, parse_ids


@pytest.fixture
def real_query(monkeypatch):
    """Undo the conftest offline patch; the transport below is still fake."""
    monkeypatch.setattr(OsvVersionAdvisories, "_query", adv._real_query_for_tests)  # noqa: SLF001


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_parse_ids():
    assert parse_ids({}) == []
    assert parse_ids({"vulns": [{"id": "B"}, {"id": "A"}, {"x": 1}, "junk"]}) == ["A", "B"]
    with pytest.raises(ValueError, match="unexpected"):
        parse_ids([])
    with pytest.raises(ValueError, match="unexpected"):
        parse_ids({"vulns": "x"})


def test_query_sends_only_name_and_version_and_caches(tmp_path, real_query):
    seen = []

    def handler(request):
        seen.append((request.url.host, request.content))
        return httpx.Response(200, json={"vulns": [{"id": "GHSA-wc69-rhjr-hc9g"}]})

    lookup = OsvVersionAdvisories(tmp_path, _client(handler))
    assert lookup("moment", "2.29.2") == ["GHSA-wc69-rhjr-hc9g"]
    assert lookup("moment", "2.29.2") == ["GHSA-wc69-rhjr-hc9g"]  # cached
    assert len(seen) == 1
    assert seen[0][0] == "api.osv.dev"
    assert b'"name":"moment"' in seen[0][1].replace(b" ", b"")


def test_errors_are_unknown(tmp_path, real_query):
    lookup = OsvVersionAdvisories(tmp_path, _client(lambda _r: httpx.Response(500)))
    assert lookup("moment", "2.29.4") is None
    assert "moment@2.29.4" in lookup.errors

    def boom(_request):
        msg = "down"
        raise httpx.ConnectError(msg)

    assert OsvVersionAdvisories(tmp_path / "b", _client(boom))("x", "1.0.0") is None


def test_conftest_keeps_tests_offline(tmp_path):
    assert OsvVersionAdvisories(tmp_path)("moment", "2.29.4") is None

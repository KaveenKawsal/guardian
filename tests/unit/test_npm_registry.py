import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from guardian.remediation import registry as registry_module
from guardian.remediation.registry import (
    ABBREVIATED_ACCEPT,
    NpmRegistry,
    parse_metadata,
    valid_package_name,
)

NOW = datetime(2026, 11, 24, tzinfo=UTC)
PACKUMENT = {
    "name": "jsonwebtoken",
    "dist-tags": {"latest": "9.0.2"},
    "versions": {
        "0.4.0": {"name": "jsonwebtoken", "version": "0.4.0", "dependencies": {"jws": "~0.2.2"}},
        "4.2.2": {"name": "jsonwebtoken", "version": "4.2.2", "deprecated": "old"},
        "9.0.0": {"name": "jsonwebtoken", "version": "9.0.0", "dependencies": {"jws": "^3.2.2"}},
        "not-semver": {"name": "jsonwebtoken"},
        "9.0.1": "garbage",
    },
}


class Recorder:
    def __init__(self, handler):
        self.handler = handler
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.handler(request)


def make(tmp_path, handler, *, now=NOW, ttl_hours=24):
    recorder = Recorder(handler)
    client = httpx.Client(transport=httpx.MockTransport(recorder))
    reg = NpmRegistry(tmp_path / "cache", client=client, ttl_hours=ttl_hours, clock=lambda: now)
    return reg, recorder


def ok(request):
    return httpx.Response(200, json=PACKUMENT)


def test_fetch_success_parses_and_validates(tmp_path):
    reg, rec = make(tmp_path, ok)
    pkg = reg.fetch("jsonwebtoken")
    assert pkg is not None
    assert sorted(pkg.versions) == ["0.4.0", "4.2.2", "9.0.0"]  # junk dropped
    assert pkg.versions["4.2.2"].deprecated == "old"
    assert pkg.versions["9.0.0"].dependencies == {"jws": "^3.2.2"}
    assert pkg.published() == ["0.4.0", "4.2.2", "9.0.0"]
    assert pkg.fetched_at == NOW
    assert not pkg.stale
    (request,) = rec.requests
    assert request.url == "https://registry.npmjs.org/jsonwebtoken"
    assert request.headers["accept"] == ABBREVIATED_ACCEPT


def test_cache_hit_skips_the_network(tmp_path):
    reg, rec = make(tmp_path, ok)
    reg.fetch("jsonwebtoken")
    again, rec2 = make(tmp_path, ok, now=NOW + timedelta(hours=1))
    pkg = again.fetch("jsonwebtoken")
    assert pkg is not None
    assert pkg.fetched_at == NOW
    assert rec2.requests == []
    assert len(rec.requests) == 1


def test_expired_cache_refetches(tmp_path):
    make(tmp_path, ok)[0].fetch("jsonwebtoken")
    later, rec = make(tmp_path, ok, now=NOW + timedelta(hours=25))
    assert later.fetch("jsonwebtoken").fetched_at == NOW + timedelta(hours=25)
    assert len(rec.requests) == 1


def test_stale_on_error(tmp_path):
    make(tmp_path, ok)[0].fetch("jsonwebtoken")

    def down(request):
        msg = "offline"
        raise httpx.ConnectError(msg, request=request)

    later, _ = make(tmp_path, down, now=NOW + timedelta(days=3))
    pkg = later.fetch("jsonwebtoken")
    assert pkg is not None
    assert pkg.stale
    assert pkg.fetched_at == NOW
    assert "unreachable" in later.errors["jsonwebtoken"]


def test_unreachable_without_cache_is_none(tmp_path):
    def down(request):
        msg = "slow"
        raise httpx.ConnectTimeout(msg, request=request)

    reg, _ = make(tmp_path, down)
    assert reg.fetch("jsonwebtoken") is None


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, content=b"not json"),
        httpx.Response(200, json=["a", "list"]),
        httpx.Response(200, json={"name": "jsonwebtoken", "versions": "nope"}),
        httpx.Response(200, json={"name": "other-package", "versions": PACKUMENT["versions"]}),
        httpx.Response(200, json={"versions": {"junk": {}}}),
        httpx.Response(404, json={"error": "Not found"}),
        httpx.Response(500),
    ],
)
def test_garbage_and_errors_are_rejected(tmp_path, response):
    reg, _ = make(tmp_path, lambda request: response)
    assert reg.fetch("jsonwebtoken") is None
    assert not list(tmp_path.glob("cache/*.json"))  # nothing invalid is cached


def test_redirects_are_not_followed(tmp_path):
    def redirect(request):
        if request.url.host != "registry.npmjs.org":
            return httpx.Response(200, json=PACKUMENT)
        return httpx.Response(301, headers={"location": "https://evil.example/jsonwebtoken"})

    reg, rec = make(tmp_path, redirect)
    assert reg.fetch("jsonwebtoken") is None
    assert [r.url.host for r in rec.requests] == ["registry.npmjs.org"]
    assert "301" in reg.errors["jsonwebtoken"]


def test_oversize_response_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(registry_module, "MAX_RESPONSE_BYTES", 1000)
    big = json.dumps({**PACKUMENT, "padding": "x" * 5000}).encode()

    def streamed(request):
        return httpx.Response(200, content=iter([big[:800], big[800:]]))

    reg, _ = make(tmp_path, streamed)
    assert reg.fetch("jsonwebtoken") is None
    assert "too large" in reg.errors["jsonwebtoken"]

    declared, _ = make(tmp_path, lambda r: httpx.Response(200, content=big))
    assert declared.fetch("jsonwebtoken") is None


def test_only_the_npm_registry_host(tmp_path):
    reg, rec = make(tmp_path, ok)
    reg.fetch("@angular/core")
    assert rec.requests[0].url.raw_path == b"/@angular%2Fcore"
    assert rec.requests[0].url.host == "registry.npmjs.org"
    for evil in ("../../etc/passwd", "a b", "", "x" * 300, "http://evil", "@scope/../x"):
        assert reg.fetch(evil) is None
    assert len(rec.requests) == 1


def test_host_guard(tmp_path, monkeypatch):
    monkeypatch.setattr(registry_module, "REGISTRY_URL", "https://evil.example/")
    reg, rec = make(tmp_path, ok)
    assert reg.fetch("jsonwebtoken") is None
    assert rec.requests == []


def test_corrupt_or_symlinked_cache_is_ignored(tmp_path):
    reg, rec = make(tmp_path, ok)
    path = reg._cache_path("jsonwebtoken")  # noqa: SLF001 - plant a corrupt cache entry
    path.parent.mkdir(parents=True)
    path.write_text("{broken")
    assert reg.fetch("jsonwebtoken") is not None
    path.write_text(json.dumps({"fetched_at": "yesterday", "versions": {}}))
    assert reg.fetch("jsonwebtoken") is not None
    assert len(rec.requests) == 2


def test_default_client_is_closed(tmp_path, monkeypatch):
    created = []

    class FakeClient(httpx.Client):
        def __init__(self, **kwargs):
            assert kwargs["follow_redirects"] is False
            super().__init__(transport=httpx.MockTransport(ok))
            created.append(self)

    monkeypatch.setattr(registry_module.httpx, "Client", FakeClient)
    reg = NpmRegistry(tmp_path / "cache", clock=lambda: NOW)
    assert reg.fetch("jsonwebtoken") is not None
    assert created[0].is_closed


def test_name_validation_and_metadata_helpers():
    assert valid_package_name("@scope/pkg.name_x")
    assert not valid_package_name("UPPER CASE")
    assert parse_metadata("x", {"versions": {}}) is None
    deps = parse_metadata(
        "x", {"versions": {"1.0.0": {"dependencies": {"ok": "^1", "bad name": "1", "n": 3}}}}
    )
    assert deps.versions["1.0.0"].dependencies == {"ok": "^1"}

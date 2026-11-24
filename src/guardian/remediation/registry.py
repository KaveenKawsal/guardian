"""npm registry facts for remediation: which versions exist, which are deprecated, and what each
version depends on.

Only ``https://registry.npmjs.org`` is contacted, with the abbreviated ("corgi") metadata format,
a timeout, no redirects and a response-size cap. Responses are validated defensively (the
registry is a third party) and cached as JSON with their fetch time; when the registry is
unreachable a stale cache entry is used instead, and with no cache the answer is ``None`` so
callers can mark versions as unverified.
"""

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from guardian.remediation import npm_semver
from guardian.remediation.advisories import OsvVersionAdvisories

REGISTRY_HOST = "registry.npmjs.org"
REGISTRY_URL = f"https://{REGISTRY_HOST}/"
ABBREVIATED_ACCEPT = "application/vnd.npm.install-v1+json"
FETCH_TIMEOUT = httpx.Timeout(20.0, connect=10.0)
MAX_RESPONSE_BYTES = 20 * 1024 * 1024
MAX_VERSIONS = 10_000
MAX_DEPENDENCIES = 2_000
MAX_TEXT = 1_000
HTTP_OK = 200
# npm package names: optional @scope/, then URL-safe characters (legacy names may be upper case).
_NAME_RE = re.compile(r"^(?:@[A-Za-z0-9-~][A-Za-z0-9._~-]*/)?[A-Za-z0-9-~][A-Za-z0-9._~-]*$")
MAX_NAME_CHARS = 214


@dataclass(frozen=True, slots=True)
class VersionMeta:
    deprecated: str | None = None
    dependencies: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class PackageVersions:
    name: str
    versions: dict[str, VersionMeta]
    fetched_at: datetime | None = None
    stale: bool = False
    """True when served from an expired cache entry because the registry was unreachable."""

    def published(self) -> list[str]:
        """Every published version, ascending by semver precedence."""
        return npm_semver.sort_versions(list(self.versions))


def valid_package_name(name: str) -> bool:
    return len(name) <= MAX_NAME_CHARS and _NAME_RE.match(name) is not None


def _text(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value[:MAX_TEXT]
    return None


def _dependencies(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    deps: dict[str, str] = {}
    for name, spec in list(value.items())[:MAX_DEPENDENCIES]:
        if isinstance(name, str) and isinstance(spec, str) and valid_package_name(name):
            deps[name] = spec[:MAX_TEXT]
    return deps


def parse_metadata(name: str, data: object) -> PackageVersions | None:
    """Validate an (abbreviated or full) packument; None when it is not usable."""
    if not isinstance(data, dict):
        return None
    if data.get("name") not in {None, name}:
        return None
    raw_versions = data.get("versions")
    if not isinstance(raw_versions, dict):
        return None
    versions: dict[str, VersionMeta] = {}
    for version, meta in list(raw_versions.items())[:MAX_VERSIONS]:
        if not isinstance(version, str) or npm_semver.parse(version) is None:
            continue
        if not isinstance(meta, dict):
            continue
        versions[version] = VersionMeta(
            deprecated=_text(meta.get("deprecated")),
            dependencies=_dependencies(meta.get("dependencies")),
        )
    if not versions:
        return None
    return PackageVersions(name=name, versions=versions)


def _serialize(pkg: PackageVersions, fetched_at: datetime) -> str:
    return json.dumps(
        {
            "fetched_at": fetched_at.isoformat(),
            "name": pkg.name,
            "versions": {
                v: {"deprecated": m.deprecated, "dependencies": m.dependencies}
                for v, m in pkg.versions.items()
            },
        },
        sort_keys=True,
    )


class RegistryError(Exception):
    """Internal: one fetch failed (network, status, size or content)."""


class NpmRegistry:
    def __init__(
        self,
        cache_dir: Path,
        client: httpx.Client | None = None,
        ttl_hours: float = 24,
        *,
        clock: Callable[[], datetime] | None = None,
        advisories: Callable[[str, str], list[str] | None] | None = None,
    ) -> None:
        self.cache_dir = cache_dir
        self.client = client
        self.advisories = advisories or OsvVersionAdvisories(
            cache_dir.parent / "osv-versions", client
        )
        """``(name, version) -> advisory ids`` for a target version (None = unknown)."""
        self.ttl = timedelta(hours=ttl_hours)
        self.clock = clock or (lambda: datetime.now(UTC))
        self.errors: dict[str, str] = {}
        """Last fetch error per package (for diagnostics; never contains credentials)."""

    # --- public --------------------------------------------------------------------------

    def fetch(self, name: str) -> PackageVersions | None:
        """Versions of ``name``; a fresh cache entry, else the registry, else a stale entry."""
        if not valid_package_name(name):
            self.errors[name] = "invalid package name"
            return None
        cached = self._read_cache(name)
        now = self.clock()
        if cached is not None and cached.fetched_at and now - cached.fetched_at < self.ttl:
            return cached
        try:
            fresh = self._download(name)
        except RegistryError as exc:
            self.errors[name] = str(exc)
            if cached is None:
                return None
            return PackageVersions(
                name=cached.name, versions=cached.versions, fetched_at=cached.fetched_at, stale=True
            )
        self._write_cache(fresh, now)
        return PackageVersions(name=fresh.name, versions=fresh.versions, fetched_at=now)

    # --- network -------------------------------------------------------------------------

    def url_for(self, name: str) -> str:
        # Scoped names keep the "@" and encode the slash: @scope%2Fname.
        return REGISTRY_URL + quote(name, safe="@")

    def _download(self, name: str) -> PackageVersions:
        own = self.client is None
        http = self.client or httpx.Client(timeout=FETCH_TIMEOUT, follow_redirects=False)
        try:
            body = self._get(http, self.url_for(name))
        finally:
            if own:
                http.close()
        try:
            data: Any = json.loads(body)
        except ValueError:
            msg = "registry returned invalid JSON"
            raise RegistryError(msg) from None
        parsed = parse_metadata(name, data)
        if parsed is None:
            msg = "registry returned unexpected metadata"
            raise RegistryError(msg)
        return parsed

    @staticmethod
    def _get(http: httpx.Client, url: str) -> bytes:
        request = http.build_request(
            "GET", url, headers={"Accept": ABBREVIATED_ACCEPT}, timeout=FETCH_TIMEOUT
        )
        if request.url.host != REGISTRY_HOST or request.url.scheme != "https":
            msg = "refusing to contact a host other than the npm registry"
            raise RegistryError(msg)
        try:
            response = http.send(request, stream=True, follow_redirects=False)
        except httpx.HTTPError as exc:
            msg = f"registry unreachable ({type(exc).__name__})"
            raise RegistryError(msg) from None
        try:
            if response.status_code != HTTP_OK:
                msg = f"registry answered HTTP {response.status_code}"
                raise RegistryError(msg)
            declared = response.headers.get("content-length", "")
            if declared.isdigit() and int(declared) > MAX_RESPONSE_BYTES:
                msg = "registry response too large"
                raise RegistryError(msg)
            chunks: list[bytes] = []
            size = 0
            try:
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > MAX_RESPONSE_BYTES:
                        msg = "registry response too large"
                        raise RegistryError(msg)
                    chunks.append(chunk)
            except httpx.HTTPError as exc:
                msg = f"registry read failed ({type(exc).__name__})"
                raise RegistryError(msg) from None
            return b"".join(chunks)
        finally:
            response.close()

    # --- cache ---------------------------------------------------------------------------

    def _cache_path(self, name: str) -> Path:
        digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:24]
        return self.cache_dir / f"{digest}.json"

    def _read_cache(self, name: str) -> PackageVersions | None:
        path = self._cache_path(name)
        try:
            if path.is_symlink() or not path.is_file():
                return None
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict):
            return None
        try:
            fetched_at = datetime.fromisoformat(str(data.get("fetched_at")))
        except ValueError:
            return None
        parsed = parse_metadata(name, data)
        if parsed is None:
            return None
        return PackageVersions(name=name, versions=parsed.versions, fetched_at=fetched_at)

    def _write_cache(self, pkg: PackageVersions, fetched_at: datetime) -> None:
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            path = self._cache_path(pkg.name)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(_serialize(pkg, fetched_at), encoding="utf-8")
            tmp.replace(path)
        except OSError:
            return  # the cache is an optimisation; a read-only home must not break remediation

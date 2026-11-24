"""Known advisories for one exact npm ``package@version`` (OSV ``/v1/query``).

The scan only knows the advisories that affect the *installed* version. A candidate's target
version can be hit by a different advisory (moment 2.29.2 fixes the 2.0.0 advisories but is
itself affected by CVE-2022-31129), which the rescan would then report as a new finding and
fail the fix. Candidates therefore prefer a target version with no known advisory.

Only the package name and version are sent (as OSV-Scanner does). One fixed HTTPS host, no
redirects, a response cap, and a 24 h cache. ``None`` means "unknown" (offline, error): the
caller must then not block a version, so remediation still works without the network.
"""

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_HOST = "api.osv.dev"
TIMEOUT = httpx.Timeout(15.0, connect=8.0)
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
HTTP_OK = 200


class OsvVersionAdvisories:
    def __init__(
        self, cache_dir: Path, client: httpx.Client | None = None, ttl_hours: float = 24
    ) -> None:
        self.cache_dir = cache_dir
        self.client = client
        self.ttl = timedelta(hours=ttl_hours)
        self.errors: dict[str, str] = {}

    def __call__(self, name: str, version: str) -> list[str] | None:
        """Advisory ids affecting ``name@version`` (``[]`` = none known, ``None`` = unknown)."""
        key = f"{name}@{version}"
        cached = self._read(key)
        if cached is not None:
            return cached
        try:
            ids = self._query(name, version)
        except (httpx.HTTPError, ValueError) as exc:
            self.errors[key] = type(exc).__name__
            return None
        self._write(key, ids)
        return ids

    def _query(self, name: str, version: str) -> list[str]:
        own = self.client is None
        http = self.client or httpx.Client(timeout=TIMEOUT, follow_redirects=False)
        try:
            request = http.build_request(
                "POST",
                OSV_QUERY_URL,
                json={"version": version, "package": {"name": name, "ecosystem": "npm"}},
                timeout=TIMEOUT,
            )
            if request.url.host != OSV_HOST or request.url.scheme != "https":
                msg = "refusing to contact a host other than api.osv.dev"
                raise ValueError(msg)
            response = http.send(request, stream=True, follow_redirects=False)
            try:
                if response.status_code != HTTP_OK:
                    msg = f"OSV answered HTTP {response.status_code}"
                    raise ValueError(msg)
                body = bytearray()
                for chunk in response.iter_bytes():
                    body += chunk
                    if len(body) > MAX_RESPONSE_BYTES:
                        msg = "OSV response too large"
                        raise ValueError(msg)
            finally:
                response.close()
        finally:
            if own:
                http.close()
        return parse_ids(json.loads(bytes(body)))

    # --- cache ---------------------------------------------------------------------------

    def _path(self, key: str) -> Path:
        return self.cache_dir / f"{hashlib.sha256(key.encode()).hexdigest()[:24]}.json"

    def _read(self, key: str) -> list[str] | None:
        path = self._path(key)
        try:
            if path.is_symlink() or not path.is_file():
                return None
            data: Any = json.loads(path.read_text(encoding="utf-8"))
            fetched = datetime.fromisoformat(str(data["fetched_at"]))
            ids = data["ids"]
        except (OSError, ValueError, KeyError, TypeError):
            return None
        if datetime.now(UTC) - fetched >= self.ttl or not isinstance(ids, list):
            return None
        return [i for i in ids if isinstance(i, str)]

    def _write(self, key: str, ids: list[str]) -> None:
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            path = self._path(key)
            tmp = path.with_suffix(".tmp")
            payload = {"fetched_at": datetime.now(UTC).isoformat(), "ids": ids}
            tmp.write_text(json.dumps(payload), encoding="utf-8")
            tmp.replace(path)
        except OSError:
            return  # the cache is an optimisation


def parse_ids(data: object) -> list[str]:
    """Advisory ids from an OSV query response (third-party data: validated, bounded)."""
    if not isinstance(data, dict):
        msg = "OSV returned unexpected JSON"
        raise ValueError(msg)  # noqa: TRY004 - surfaced as "unknown", like a network error
    vulns = data.get("vulns") or []
    if not isinstance(vulns, list):
        msg = "OSV returned unexpected vulns"
        raise ValueError(msg)  # noqa: TRY004
    ids = [v["id"] for v in vulns if isinstance(v, dict) and isinstance(v.get("id"), str)]
    return sorted({i[:64] for i in ids})[:50]


_real_query_for_tests = OsvVersionAdvisories._query  # noqa: SLF001 - restored by tests

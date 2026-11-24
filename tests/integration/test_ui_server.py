"""The review console on a real socket: ephemeral port, threaded server, httpx client."""

import socket
import threading
from datetime import UTC, datetime

import httpx
import pytest

from guardian.core.config import GuardianSettings
from guardian.core.models import GitInfo, Priority, RepositoryProfile
from guardian.core.remediation_models import CaseStatus, RemediationCase
from guardian.storage.database import Database
from guardian.ui import decisions as decisions_module
from guardian.ui.server import MAX_BODY_BYTES, ConsoleApp, make_server

T0 = datetime(2026, 1, 1, tzinfo=UTC)
CASE_ID = "rc_0123456789ab"


@pytest.fixture
def running(tmp_path, monkeypatch):
    monkeypatch.setattr(decisions_module.getpass, "getuser", lambda: "alice")
    settings = GuardianSettings(_env_file=None, data_dir=tmp_path, cli_approvers=["alice"])
    with Database(settings.database_path) as db:
        repo_id = db.repositories.upsert("/r", "r")
        profile = RepositoryProfile(
            name="r",
            root="/r",
            profiled_at=T0,
            total_files=1,
            total_bytes=1,
            git=GitInfo(is_repository=True),
        )
        db.scans.create("s1", repo_id, T0, profile)
        db.remediation.create(
            RemediationCase(
                id=CASE_ID,
                fingerprint="f" * 40,
                scan_id="s1",
                repository_root="/r",
                title="minimist 1.2.5",
                priority=Priority.P1,
                created_at=T0,
                updated_at=T0,
            )
        )
        db.remediation.update_status(CASE_ID, CaseStatus.AWAITING_DECISION)

    app = ConsoleApp(settings, port=0)  # default handler: record_decision_transition
    server = make_server(app, 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{app.port}"
    try:
        yield app, base, settings
    finally:
        server.shutdown()
        server.server_close()


def test_serves_page_and_api(running):
    app, base, _settings = running
    assert app.launch_url.startswith(f"{base}/?token=")
    with httpx.Client(base_url=base, timeout=5) as client:
        page = client.get(f"/?token={app.token}")
        assert page.status_code == 200
        assert page.headers["content-type"].startswith("text/html")
        assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
        assert client.get("/app.js").headers["content-type"].startswith("text/javascript")
        assert client.head("/app.css").status_code == 200
        assert client.get("/../pyproject.toml").status_code == 404

        assert client.get("/api/cases").status_code == 401
        headers = {"X-Guardian-Token": app.token}
        cases = client.get("/api/cases", headers=headers).json()["cases"]
        assert [c["id"] for c in cases] == [CASE_ID]

        evil = client.get("/api/cases", headers=headers | {"Host": "attacker.example"})
        assert evil.status_code == 421

        response = client.post(
            f"/api/cases/{CASE_ID}/decision",
            headers=headers | {"Origin": base},
            json={"action": "accept"},
        )
        assert response.status_code == 202, response.text
        for thread in app.decisions.threads:
            thread.join(timeout=5)
        detail = client.get(f"/api/cases/{CASE_ID}", headers=headers).json()
        assert detail["case"]["status"] == "APPROVED"
        assert detail["decisions"][0]["channel"] == "cli"
        assert client.get("/api/audit/verify", headers=headers).json()["ok"] is True

        assert client.put("/api/cases", headers=headers).status_code == 405


def _raw(port, request: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(request)
        chunks = []
        while chunk := sock.recv(65536):
            chunks.append(chunk)
    return b"".join(chunks)


def test_body_cap_and_length_required_on_socket(running):
    app, _, _ = running
    host = f"127.0.0.1:{app.port}"
    big = _raw(
        app.port,
        (
            f"POST /api/cases/{CASE_ID}/decision HTTP/1.1\r\nHost: {host}\r\n"
            f"X-Guardian-Token: {app.token}\r\nContent-Type: application/json\r\n"
            f"Content-Length: {MAX_BODY_BYTES + 1}\r\nConnection: close\r\n\r\n"
        ).encode(),
    )
    assert big.startswith(b"HTTP/1.1 413")
    no_length = _raw(
        app.port,
        (
            f"POST /api/cases/{CASE_ID}/decision HTTP/1.1\r\nHost: {host}\r\n"
            f"X-Guardian-Token: {app.token}\r\nConnection: close\r\n\r\n"
        ).encode(),
    )
    assert no_length.startswith(b"HTTP/1.1 411")
    delete = _raw(
        app.port, f"DELETE / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
    )
    assert delete.startswith(b"HTTP/1.1 405")
    assert app.token.encode() not in big + no_length + delete

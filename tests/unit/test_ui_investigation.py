"""Console API for the architecture view, the codebase view, case investigations and
``POST /api/investigate``."""

import json
import threading
from datetime import UTC, datetime

import pytest
from investigation_fakes import routes
from investigation_world import SCAN_ID, seed_ai_scan

from guardian.core.config import GuardianSettings
from guardian.core.models import Priority
from guardian.core.remediation_models import RemediationCase, case_id_for, fingerprint_for
from guardian.investigation.models import TraceEvent
from guardian.orchestration.investigation_graph import run_investigation
from guardian.storage.database import Database
from guardian.ui.investigation import InvestigationJobs
from guardian.ui.server import ConsoleApp, static_asset

TOKEN = "tok-investigate"  # noqa: S105
PORT = 8765
HOST = f"127.0.0.1:{PORT}"


@pytest.fixture(autouse=True)
def _no_real_providers(monkeypatch):
    """No test may reach Groq or Gemini, even when keys sit in .env or the environment."""
    for key in ("GROQ_API_KEY", "GOOGLE_API_KEY", "GUARDIAN_LLM_PROVIDER", "GUARDIAN_LLM_MODEL"):
        monkeypatch.delenv(key, raising=False)

    def refuse(*_args, **_kwargs):
        msg = "tests must use fake chat models"
        raise AssertionError(msg)

    monkeypatch.setattr("guardian.investigation.runner.build_chat_model", refuse)
    monkeypatch.setattr("guardian.llm.providers.build_chat_model", refuse)


@pytest.fixture
def env(tmp_path):
    settings = GuardianSettings(
        _env_file=None,
        data_dir=tmp_path / "data",
        cli_approvers=["alice"],
        groq_api_key="gsk_never_shown_123",
    )
    with Database(settings.database_path) as db:
        world, _ = seed_ai_scan(db, tmp_path / "juice-shop")
        jwt = world.package_findings("jsonwebtoken")
        fp = fingerprint_for(str(tmp_path / "juice-shop"), "pkg:npm/jsonwebtoken@0.4.0", "jwt")
        case = db.remediation.create(
            RemediationCase(
                id=case_id_for(fp),
                fingerprint=fp,
                scan_id=SCAN_ID,
                repository_root=str(tmp_path / "juice-shop"),
                finding_ids=[f.id for f in jwt],
                title="jsonwebtoken 0.4.0",
                priority=Priority.P1,
                created_at=datetime(2026, 1, 1, tzinfo=UTC),
                updated_at=datetime(2026, 1, 1, tzinfo=UTC),
            )
        )
    gate = threading.Event()
    started = []

    def job(s, top, on_event):
        started.append(top)
        on_event(
            TraceEvent(
                node="code", event="finished", at=datetime.now(UTC), agent="code", status="ok"
            )
        )
        gate.wait(5)
        return "ir_test"

    app = ConsoleApp(settings, token=TOKEN, port=PORT, jobs=InvestigationJobs(settings, job))
    return app, settings, case, gate, started


def call(app, method, path, body=None, *, token=TOKEN, headers=None):
    hdrs = {"host": HOST}
    if token is not None:
        hdrs["x-guardian-token"] = token
    data = b""
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        hdrs["content-type"] = "application/json"
    hdrs |= headers or {}
    response = app.handle(method, path, hdrs, data)
    return response, json.loads(response.body)


def investigate(settings):
    with Database(settings.database_path) as db:
        return run_investigation(db, settings, SCAN_ID, routes=routes())


def test_architecture_before_any_run(env):
    app, *_ = env
    response, body = call(app, "GET", "/api/architecture")
    assert response.status == 200
    assert response.headers["Cache-Control"] == "no-store"
    nodes = {n["id"]: n for n in body["nodes"]}
    expected = {
        "profile",
        "sbom",
        "osv",
        "semgrep",
        "git",
        "indexer",
        "graph",
        "risk",
        "agent-architect",
        "agent-dependency",
        "agent-vulnerability",
        "agent-code",
        "agent-correlator",
        "cases",
        "decision",
        "apply",
        "sandbox",
        "rescan",
        "verdict",
    }
    assert set(nodes) == expected
    assert nodes["sbom"]["status"] == "partial"  # npm-lockfile failed, cdxgen ran
    assert ["npm-lockfile", "failed, 34.0s: no network"] in nodes["sbom"]["details"]
    assert nodes["semgrep"]["status"] == "success"
    assert nodes["semgrep"]["kind"] == "tool"
    assert nodes["agent-code"]["kind"] == "ai"
    assert nodes["agent-code"]["status"] == "not_run"
    assert nodes["decision"]["kind"] == "human"
    assert nodes["cases"]["summary"] == "1 cases"
    assert body["investigation"] is None
    assert body["job"]["running"] is False
    assert ["cases", "decision"] in body["edges"]
    assert "gsk_never_shown_123" not in response.body.decode()


def test_architecture_and_codebase_after_run(env):
    app, settings, *_ = env
    run, _ = investigate(settings)
    _, body = call(app, "GET", "/api/architecture")
    nodes = {n["id"]: n for n in body["nodes"]}
    code = nodes["agent-code"]
    assert code["status"] == "success"
    details = dict(code["details"])
    assert details["Provider / model"] == "groq / fake-fast"
    assert details["LLM calls"] == "2"
    assert dict(nodes["agent-architect"]["details"])["Provider / model"] == "google / fake-deep"
    assert body["investigation"]["id"] == run.id
    assert body["investigation"]["calls"] == len(run.provider_calls)

    _, cb = call(app, "GET", "/api/codebase")
    modules = {m["area"]: m for m in cb["modules"]}
    assert modules["data/static/codefixes"]["path_classification"] == "challenge-fixture"
    assert modules["test"]["path_classification"] == "test"
    assert modules["routes"]["ai"]["purpose"] == "Purpose of routes"
    assert cb["profile"]["entry_points"] == 2
    findings = {f["id"]: f for f in cb["code_findings"]}
    login = findings["code-login"]
    assert login["path_classification"] == "prod"
    assert login["code_investigator"]["assessment"]["source"] == "inferred"
    assert login["code_investigator"]["agent_label"] == "Code Investigator"
    assert login["correlator"]["assessment"]["confidence"] == "medium"
    assert findings["code-fix"]["path_classification"] == "challenge-fixture"
    assert cb["architect"]["status"] == "ok"


def test_case_detail_includes_investigation(env):
    app, settings, case, *_ = env
    _, before = call(app, "GET", f"/api/cases/{case.id}")
    assert before["investigation"] is None
    investigate(settings)
    _, body = call(app, "GET", f"/api/cases/{case.id}")
    inv = body["investigation"]
    assert [r["agent"] for r in inv["reports"]] == ["dependency", "vulnerability", "correlator"]
    for report in inv["reports"]:
        assert report["subject_kind"] == "case"
        assert report["verified_facts"]
        assert all(f["source"] == "verified" for f in report["verified_facts"])
        assert report["assessment"]["source"] == "inferred"
        assert report["provider"] in {"groq", "google"}


def test_empty_database_views(tmp_path):
    settings = GuardianSettings(_env_file=None, data_dir=tmp_path)
    app = ConsoleApp(settings, token=TOKEN, port=PORT)
    assert call(app, "GET", "/api/architecture")[1]["scan"] is None
    assert call(app, "GET", "/api/codebase")[1] == {"scan": None}
    response, body = call(app, "POST", "/api/investigate", {"top": 2})
    assert response.status == 404
    assert "guardian scan" in body["error"]


def test_post_investigate_auth_and_conflict(env):
    app, _, _, gate, started = env
    assert call(app, "POST", "/api/investigate", {"top": 3}, token=None)[0].status == 401
    assert call(app, "POST", "/api/investigate", {"top": 3}, token="wrong")[0].status == 401  # noqa: S106
    cross = call(
        app, "POST", "/api/investigate", {"top": 3}, headers={"origin": "http://evil.example"}
    )
    assert cross[0].status == 403
    response, body = call(app, "POST", "/api/investigate", {"top": 3})
    assert response.status == 202
    assert body["job"]["running"] is True
    response, body = call(app, "POST", "/api/investigate", {"top": 3})
    assert response.status == 409
    assert "already running" in body["error"]
    _, status = call(app, "GET", "/api/investigate")
    assert status["running"] is True
    _, arch = call(app, "GET", "/api/architecture")
    assert {n["id"]: n for n in arch["nodes"]}["agent-code"]["status"] == "running"
    gate.set()
    app.jobs.thread.join(5)
    _, status = call(app, "GET", "/api/investigate")
    assert status["running"] is False
    assert status["run_id"] == "ir_test"
    assert status["events"][0]["agent"] == "code"
    assert started == [3]


def test_post_investigate_validates_body(env):
    app, *_ = env
    assert call(app, "POST", "/api/investigate", {"top": 0})[0].status == 400
    assert call(app, "POST", "/api/investigate", {"top": True})[0].status == 400
    assert call(app, "POST", "/api/investigate", {"other": 1})[0].status == 400
    assert call(app, "POST", "/api/investigate", b"{nope")[0].status == 400
    response, _ = call(
        app, "POST", "/api/investigate", b"top=1", headers={"content-type": "text/plain"}
    )
    assert response.status == 415
    assert call(app, "PUT", "/api/investigate")[0].status == 405


def test_post_investigate_without_body_uses_default(env):
    app, _, _, gate, started = env
    gate.set()
    response, _ = call(app, "POST", "/api/investigate")
    assert response.status == 202
    app.jobs.thread.join(5)
    assert started == [5]


def test_job_failure_is_reported(tmp_path):
    settings = GuardianSettings(_env_file=None, data_dir=tmp_path)

    def broken(s, top, on_event):
        msg = "secret detail"
        raise RuntimeError(msg)

    jobs = InvestigationJobs(settings, broken)
    jobs.start(1)
    jobs.thread.join(5)
    status = jobs.status()
    assert status["running"] is False
    assert status["error"] == "Investigation failed (RuntimeError)."


def test_default_job_runs_on_its_own_connection(env, monkeypatch):
    _, settings, *_ = env
    from guardian.orchestration import investigation_graph
    from guardian.ui import investigation as ui_investigation

    original = investigation_graph.run_investigation

    def no_ai(db, s, scan_id, **kwargs):
        return original(
            db, s, scan_id, no_ai=True, **{k: v for k, v in kwargs.items() if k != "no_ai"}
        )

    monkeypatch.setattr(investigation_graph, "run_investigation", no_ai)
    jobs = InvestigationJobs(settings)
    jobs.start(1)
    jobs.thread.join(30)
    status = jobs.status()
    assert status["error"] is None
    assert status["run_id"].startswith("ir_")
    assert any(e["node"] == "persist" for e in status["events"])
    assert ui_investigation.default_job is jobs.runner


def test_static_assets_stay_text_only():
    html = static_asset("index.html").decode()
    for view in ("cases", "architecture", "codebase"):
        assert f'id="view-{view}"' in html
    js = static_asset("app.js").decode()
    for sink in (
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "new Function",
    ):
        assert sink not in js
    assert "createElementNS" in js
    assert "/api/architecture" in js
    assert "/api/investigate" in js
    css = static_asset("app.css").decode()
    assert "url(" not in css
    assert "@import" not in css

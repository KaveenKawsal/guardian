import json
from datetime import UTC, date, datetime, timedelta

import pytest

from guardian.core.config import GuardianSettings
from guardian.core.models import (
    Confidence,
    Evidence,
    EvidenceKind,
    Finding,
    FindingKind,
    GitInfo,
    Priority,
    RepositoryProfile,
    RiskAssessment,
    RiskFactor,
    RiskFactorName,
    Severity,
    VulnerabilityDetails,
)
from guardian.core.remediation_models import (
    CaseStatus,
    DecisionType,
    DeclineReason,
    HumanDecision,
    RemediationActionType,
    RemediationCandidate,
    RemediationCase,
    RemediationPlan,
    SbomDiff,
    SemverJump,
    StepStatus,
    ValidationRun,
    ValidationStep,
    VerificationResult,
    VerificationStatus,
    candidate_id_for,
    case_id_for,
    fingerprint_for,
)
from guardian.storage.database import Database
from guardian.ui import decisions as decisions_module
from guardian.ui import payloads
from guardian.ui.decisions import DecisionService, command_line
from guardian.ui.server import MAX_BODY_BYTES, STATIC_FILES, ConsoleApp, static_asset

T0 = datetime(2026, 1, 1, tzinfo=UTC)
ROOT = "/work/juice-shop"
TOKEN = "test-token-123"  # noqa: S105
PORT = 8765
HOST = f"127.0.0.1:{PORT}"


def make_settings(tmp_path, approvers=("alice",)):
    return GuardianSettings(
        _env_file=None,
        data_dir=tmp_path,
        cli_approvers=list(approvers),
        approvers=["jira-acc-1"],
        jira_base_url=None,
        jira_email=None,
        jira_api_token=None,
        jira_project_key=None,
        groq_api_key="gsk_secret_value",
    )


def _finding(fid, package="lodash", version="4.17.20", vuln="CVE-2021-23337"):
    return Finding(
        id=fid,
        kind=FindingKind.VULNERABILITY,
        title=f"{package} {version}: <img src=x onerror=alert(1)>",
        severity=Severity.HIGH,
        tool="osv-scanner",
        component_ref=f"pkg:npm/{package}@{version}",
        details=VulnerabilityDetails(
            vulnerability_id=vuln,
            package=package,
            version=version,
            ecosystem="npm",
            fixed_versions=["4.17.21"],
            summary="Command injection",
        ),
        evidence=[
            Evidence(
                kind=EvidenceKind.ADVISORY,
                tool="osv-scanner",
                summary="OSV advisory",
                url="https://osv.dev/vulnerability/GHSA-x",
            )
        ],
    )


def _case(vuln, finding_id, status_title):
    fp = fingerprint_for(ROOT, "pkg:npm/lodash@4.17.20", vuln)
    return RemediationCase(
        id=case_id_for(fp),
        fingerprint=fp,
        scan_id="s1",
        repository_root=ROOT,
        finding_ids=[finding_id],
        title=status_title,
        priority=Priority.P2,
        created_at=T0,
        updated_at=T0,
    )


def _candidate(case, to_version):
    return RemediationCandidate(
        id=candidate_id_for(
            case.fingerprint, RemediationActionType.UPGRADE, "pkg:npm/lodash", to_version
        ),
        case_id=case.id,
        finding_ids=case.finding_ids,
        action_type=RemediationActionType.UPGRADE,
        component="pkg:npm/lodash",
        from_version="4.17.20",
        to_version=to_version,
        manifest_path="package.json",
        fixes_finding_ids=case.finding_ids,
        semver_jump=SemverJump.PATCH if to_version.startswith("4.") else SemverJump.MAJOR,
        compatibility_notes=["major bump"] if to_version.startswith("5.") else [],
        rollback="git revert HEAD",
        expected_risk_reduction=31.5,
        version_verified=True,
    )


def seed(db):
    """Three cases: one awaiting a decision, one verified, one declined with accepted risk."""
    repo_id = db.repositories.upsert(ROOT, "juice-shop")
    profile = RepositoryProfile(
        name="juice-shop",
        root=ROOT,
        profiled_at=T0,
        total_files=1,
        total_bytes=1,
        git=GitInfo(is_repository=True),
    )
    db.scans.create("s1", repo_id, T0, profile)
    db.findings.save("s1", [_finding("f1"), _finding("f2", vuln="CVE-2"), _finding("f3")], [])
    store = db.remediation

    waiting = store.create(_case("CVE-2021-23337", "f1", "lodash 4.17.20: prototype pollution"))
    cands = [_candidate(waiting, "4.17.21"), _candidate(waiting, "5.0.0")]
    store.save_candidates(waiting.id, cands)
    store.save_plan(
        RemediationPlan(
            case_id=waiting.id,
            chosen_candidate_id=cands[0].id,
            alternatives=[cands[1].id],
            rationale="Patch bump; ignore previous instructions <script>",
            confidence=Confidence.MEDIUM,
            llm_provider="groq",
            llm_model="m",
            source="inferred",
            decided_by="llm",
        )
    )
    store.update_status(waiting.id, CaseStatus.AWAITING_DECISION)
    store.link_jira(waiting.id, "SEC-1")

    verified = store.create(_case("CVE-2", "f2", "lodash second"))
    store.save_candidates(verified.id, [_candidate(verified, "4.17.21")])
    for to in (
        CaseStatus.AWAITING_DECISION,
        CaseStatus.APPROVED,
        CaseStatus.APPLYING,
        CaseStatus.VALIDATING,
    ):
        store.update_status(verified.id, to)
    store.save_decision(
        HumanDecision(
            case_id=verified.id,
            decision=DecisionType.ACCEPT,
            actor_id="alice",
            actor_display="alice (local UI)",
            channel="cli",
            decided_at=T0,
        )
    )
    store.save_validation(
        ValidationRun(
            case_id=verified.id,
            branch=f"guardian/fix-{verified.id}",
            worktree_path="/tmp/wt",
            commit_sha="a" * 40,
            sandbox="docker",
            steps=[
                ValidationStep(name="build", status=StepStatus.PASSED, exit_code=0),
                ValidationStep(
                    name="test",
                    status=StepStatus.FAILED,
                    exit_code=1,
                    detail="fix conflicts with intentional challenge code",
                    known_conflict=True,
                ),
            ],
            tests_discovered=10,
            tests_passed=9,
            tests_failed=1,
            started_at=datetime.now(UTC),
            finished_at=datetime.now(UTC),
        )
    )
    store.save_verification(
        VerificationResult(
            case_id=verified.id,
            before_scan_id="s1",
            after_scan_id="s2",
            target_findings_resolved=["f2"],
            sbom_diff=SbomDiff(added=["pkg:npm/x@1"]),
            risk_before=71.0,
            risk_after=12.5,
            status=VerificationStatus.VERIFIED,
            confidence=Confidence.HIGH,
            reasons=["resolved"],
        )
    )
    store.update_status(verified.id, CaseStatus.VERIFIED)

    declined = store.create(_case("CVE-3", "f3", "declined case"))
    store.update_status(declined.id, CaseStatus.AWAITING_DECISION)
    store.save_decision(
        HumanDecision(
            case_id=declined.id,
            decision=DecisionType.DECLINE,
            decline_reason=DeclineReason.ACCEPTED_RISK,
            risk_acceptance_expires=date(2027, 1, 1),
            justification="training vuln",
            actor_id="alice",
            actor_display="alice",
            channel="cli",
            decided_at=T0,
        )
    )
    store.update_status(declined.id, CaseStatus.DECLINED)
    store.update_status(declined.id, CaseStatus.CLOSED)
    return waiting, cands, verified, declined


class Recorder:
    def __init__(self):
        self.calls = []

    def __call__(self, case, decision):
        self.calls.append((case, decision))


def fake_risk(db, scan_id):
    return {
        "f1": RiskAssessment(
            finding_id="f1",
            score=71.0,
            known_weight=0.8,
            confidence=Confidence.MEDIUM,
            priority=Priority.P2,
            factors=[
                RiskFactor(name=RiskFactorName.SEVERITY, weight=0.35, value=0.8, rationale="high"),
                RiskFactor(name=RiskFactorName.EXPLOITABILITY, weight=0.2, rationale="unknown"),
            ],
            summary="P2 because high severity",
        )
    }


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(decisions_module.getpass, "getuser", lambda: "alice")
    settings = make_settings(tmp_path)
    with Database(settings.database_path) as db:
        seeded = seed(db)
    recorder = Recorder()
    app = ConsoleApp(
        settings,
        token=TOKEN,
        port=PORT,
        handler=recorder,
        risk=payloads.RiskCache(fake_risk),
    )
    return app, recorder, seeded, settings


def call(app, method, path, body=None, *, headers=None, token=TOKEN, raw=None):
    hdrs = {"host": HOST}
    if token is not None:
        hdrs["x-guardian-token"] = token
    data = b""
    if body is not None:
        data = json.dumps(body).encode()
        hdrs["content-type"] = "application/json"
    if raw is not None:
        data = raw
    hdrs |= headers or {}
    response = app.handle(method, path, hdrs, data)
    try:
        payload = json.loads(response.body)
    except ValueError:
        payload = None
    return response, payload


def wait_threads(app):
    for thread in app.decisions.threads:
        thread.join(timeout=5)


# --- reads ------------------------------------------------------------------------------


def test_case_list_sorted_with_summary_fields(env):
    app, _, (waiting, _, verified, declined), _ = env
    response, body = call(app, "GET", "/api/cases")
    assert response.status == 200
    ids = [c["id"] for c in body["cases"]]
    assert set(ids) == {waiting.id, verified.id, declined.id}
    first = next(c for c in body["cases"] if c["id"] == waiting.id)
    assert first["status"] == "AWAITING_DECISION"
    assert first["priority"] == "P2"
    assert first["priority_label"] == "high"
    assert first["jira_key"] == "SEC-1"
    assert first["jira_url"] is None  # no base URL configured
    assert first["live"] is False
    assert response.headers["Cache-Control"] == "no-store"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Referrer-Policy"] == "no-referrer"


def test_case_detail_payload(env):
    app, _, (waiting, cands, _, _), _ = env
    response, body = call(app, "GET", f"/api/cases/{waiting.id}")
    assert response.status == 200
    assert body["case"]["id"] == waiting.id
    assert body["findings"][0]["id"] == "f1"
    assert body["findings"][0]["source"] == "verified"
    assert body["findings"][0]["evidence"][0]["url"].startswith("https://osv.dev")
    assert body["risk"][0]["score"] == 71.0
    assert body["risk"][0]["factors"][1]["value"] is None
    assert body["risk_note"] is None
    rec = [c for c in body["candidates"] if c["recommended"]]
    assert [c["id"] for c in rec] == [cands[0].id]
    other = next(c for c in body["candidates"] if not c["recommended"])
    assert other["compatibility_notes"] == ["major bump"]
    assert {"rollback", "expected_risk_reduction", "version_verified"} <= set(other)
    assert body["plan"]["source"] == "inferred"
    assert body["jira"]["issue_key"] == "SEC-1"
    assert [e["event"] for e in body["audit"]][:2] == [
        "case:created",
        "status:PROPOSED->AWAITING_DECISION",
    ]
    stations = {s["key"]: s["state"] for s in body["journey"]["stations"]}
    assert stations["decision"] == "current"
    assert stations["risk"] == stations["fix"] == "done"


def test_verified_case_detail_has_validation_and_verification(env):
    app, _, (_, _, verified, _), _ = env
    _, body = call(app, "GET", f"/api/cases/{verified.id}")
    step = body["validations"][0]["steps"][1]
    assert step["known_conflict"] is True
    assert step["detail"] == "fix conflicts with intentional challenge code"
    ver = body["verifications"][0]
    assert ver["status"] == "VERIFIED"
    assert (ver["risk_before"], ver["risk_after"]) == (71.0, 12.5)
    assert ver["sbom_diff"]["added"] == ["pkg:npm/x@1"]
    assert {s["state"] for s in body["journey"]["stations"]} == {"done"}
    assert body["risk"] == []  # fake risk only knows f1
    assert body["risk_note"]


def test_declined_case_shows_branch(env):
    app, _, (_, _, _, declined), _ = env
    _, body = call(app, "GET", f"/api/cases/{declined.id}")
    journey = body["journey"]
    assert journey["branch"]["reason"] == "ACCEPTED_RISK"
    assert journey["branch"]["until"] == "2027-01-01"
    assert journey["stations"][-1]["state"] == "skipped"


def test_unknown_case_and_route(env):
    app, *_ = env
    assert call(app, "GET", "/api/cases/rc_000000000000")[0].status == 404
    assert call(app, "GET", "/api/nope")[0].status == 404
    assert call(app, "GET", "/api/cases/../../etc")[0].status == 404
    assert call(app, "PUT", "/api/cases")[0].status == 405


def test_audit_verify(env):
    app, *_ = env
    response, body = call(app, "GET", "/api/audit/verify")
    assert response.status == 200
    assert body["ok"] is True
    assert body["events"] > 5
    assert body["problems"] == []


def test_health_has_no_secrets(env):
    app, *_ = env
    response, body = call(app, "GET", "/api/health")
    assert response.status == 200
    assert body == {
        "db_ok": True,
        "db_error": None,
        "jira_configured": False,
        "cli_approvers_configured": True,
        "pr_enabled": False,
    }
    text = response.body.decode()
    for secret in ("gsk_secret_value", "alice", "jira-acc-1", TOKEN):
        assert secret not in text


def test_health_reports_database_error(tmp_path):
    settings = make_settings(tmp_path)
    settings.data_dir.joinpath("guardian.db").mkdir(parents=True)  # a directory: cannot open
    app = ConsoleApp(settings, token=TOKEN, port=PORT)
    _, body = call(app, "GET", "/api/health")
    assert body["db_ok"] is False
    assert body["db_error"]


def test_risk_unavailable_note(env):
    app, _, (waiting, *_), _settings = env

    def broken(db, scan_id):
        raise RuntimeError

    app.risk = payloads.RiskCache(broken)
    _, body = call(app, "GET", f"/api/cases/{waiting.id}")
    assert body["risk"] == []
    assert "unavailable" in body["risk_note"]
    # cached: the loader is not called again
    assert app.risk.get(None, "s1") == body["risk_note"]


def test_real_risk_loader_fails_soft_without_sbom(env):
    app, _, (waiting, *_), _ = env
    app.risk = payloads.RiskCache()
    _, body = call(app, "GET", f"/api/cases/{waiting.id}")
    assert body["risk"] == [] or body["risk"][0]["finding_id"] == "f1"


# --- security checks ------------------------------------------------------------------


def test_token_required(env):
    app, *_ = env
    assert call(app, "GET", "/api/cases", token=None)[0].status == 401
    assert call(app, "GET", "/api/cases", token="wrong")[0].status == 401  # noqa: S106
    assert call(app, "GET", "/api/health", token="")[0].status == 401
    assert call(app, "POST", "/api/cases/rc_000000000000/decision", {}, token=None)[0].status == 401


@pytest.mark.parametrize(
    "host", ["evil.example:8765", "127.0.0.1:9999", "localhost", "", "127.0.0.1.nip.io:8765"]
)
def test_host_header_rejected(env, host):
    app, *_ = env
    response, _ = call(app, "GET", "/api/cases", headers={"host": host})
    assert response.status == 421
    assert call(app, "GET", "/", headers={"host": host})[0].status == 421


def test_localhost_host_accepted(env):
    app, *_ = env
    assert call(app, "GET", "/api/cases", headers={"host": "localhost:8765"})[0].status == 200


def test_origin_mismatch_rejected(env):
    app, _, (waiting, *_), _ = env
    response, _ = call(app, "GET", "/api/cases", headers={"origin": "http://evil.example"})
    assert response.status == 403
    response, _ = call(
        app,
        "POST",
        f"/api/cases/{waiting.id}/decision",
        {"action": "accept"},
        headers={"origin": "http://localhost:9999"},
    )
    assert response.status == 403
    ok, _ = call(app, "GET", "/api/cases", headers={"origin": "http://127.0.0.1:8765"})
    assert ok.status == 200


def test_body_cap_and_json_only(env):
    app, recorder, (waiting, *_), _ = env
    path = f"/api/cases/{waiting.id}/decision"
    big = b"{" + b" " * MAX_BODY_BYTES + b"}"
    response, _ = call(app, "POST", path, raw=big, headers={"content-type": "application/json"})
    assert response.status == 413
    response, _ = call(
        app, "POST", path, raw=b"action=accept", headers={"content-type": "text/plain"}
    )
    assert response.status == 415
    response, _ = call(
        app, "POST", path, raw=b"{nope", headers={"content-type": "application/json"}
    )
    assert response.status == 400
    response, _ = call(app, "POST", path, raw=b"[1]", headers={"content-type": "application/json"})
    assert response.status == 400
    assert call(app, "GET", path)[0].status == 405
    assert recorder.calls == []


def test_static_allowlist_and_traversal(env):
    app, *_ = env
    for path in STATIC_FILES:
        response, _ = call(app, "GET", path, token=None)
        assert response.status == 200
        assert response.headers["Content-Security-Policy"].startswith("default-src 'self'")
    assert call(app, "GET", "/?token=abc", token=None)[0].status == 200
    for path in (
        "/../server.py",
        "/static/app.js",
        "/%2e%2e/server.py",
        "/app.js/../../decisions.py",
        "/__init__.py",
        "/etc/passwd",
        "//app.js",
    ):
        assert call(app, "GET", path, token=None)[0].status == 404, path
    assert call(app, "POST", "/app.js", token=None)[0].status == 405


def test_index_references_only_local_assets():
    html = static_asset("index.html").decode()
    assert 'src="/app.js"' in html
    assert 'href="/app.css"' in html
    assert "http://" not in html
    assert "https://" not in html
    assert "<style" not in html
    assert "onclick" not in html
    css = static_asset("app.css").decode()
    assert "@import" not in css
    assert "url(" not in css
    js = static_asset("app.js").decode()
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
        assert sink not in js


# --- decisions --------------------------------------------------------------------------


def test_accept_recommended_calls_handler(env):
    app, recorder, (waiting, *_), _ = env
    response, body = call(app, "POST", f"/api/cases/{waiting.id}/decision", {"action": "accept"})
    assert response.status == 202, body
    wait_threads(app)
    assert len(recorder.calls) == 1
    case, decision = recorder.calls[0]
    assert case.id == waiting.id
    assert isinstance(decision, HumanDecision)
    assert decision.channel == "cli"
    assert decision.decision is DecisionType.ACCEPT
    assert decision.actor_id == "alice"
    assert decision.actor_display == "alice (local UI)"
    assert body["recorded"] == "accept"
    with Database(app.settings.database_path) as db:
        assert db.remediation.decisions(waiting.id)[-1] == decision
        assert db.audit.list(waiting.id)[-1].event == "decision:recorded"
        assert db.audit.list(waiting.id)[-1].actor == "cli:alice"


def test_accept_selected_candidate(env):
    app, recorder, (waiting, cands, *_), _ = env
    response, _ = call(
        app,
        "POST",
        f"/api/cases/{waiting.id}/decision",
        {"action": "accept", "candidate_id": cands[1].id},
    )
    assert response.status == 202
    wait_threads(app)
    assert recorder.calls[0][1].candidate_id == cands[1].id


def test_modify_version(env):
    app, recorder, (waiting, *_), _ = env
    response, _ = call(
        app, "POST", f"/api/cases/{waiting.id}/decision", {"action": "modify", "version": "4.17.22"}
    )
    assert response.status == 202
    wait_threads(app)
    decision = recorder.calls[0][1]
    assert decision.decision is DecisionType.MODIFY
    assert decision.modify.version == "4.17.22"


def test_decline_accepted_risk(env):
    app, recorder, (waiting, *_), _ = env
    until = (datetime.now(UTC).date() + timedelta(days=30)).isoformat()
    response, _ = call(
        app,
        "POST",
        f"/api/cases/{waiting.id}/decision",
        {
            "action": "decline",
            "decline_reason": "accepted_risk",
            "until": until,
            "justification": "Intentional training vulnerability",
        },
    )
    assert response.status == 202
    wait_threads(app)
    decision = recorder.calls[0][1]
    assert decision.decline_reason is DeclineReason.ACCEPTED_RISK
    assert decision.risk_acceptance_expires.isoformat() == until
    assert decision.justification == "Intentional training vulnerability"


def test_unauthorized_user_403(env, monkeypatch):
    app, recorder, (waiting, *_), _ = env
    monkeypatch.setattr(decisions_module.getpass, "getuser", lambda: "mallory")
    app.decisions = DecisionService(app.settings, recorder)  # default user lookup
    response, body = call(app, "POST", f"/api/cases/{waiting.id}/decision", {"action": "accept"})
    assert response.status == 403
    assert "GUARDIAN_CLI_APPROVERS" in body["error"]
    assert "mallory" in body["error"]
    assert recorder.calls == []
    with Database(app.settings.database_path) as db:
        assert db.remediation.decisions(waiting.id) == []
        assert db.audit.list(waiting.id)[-1].event == "cli:unauthorized"


def test_parse_error_400_with_grammar(env):
    app, recorder, (waiting, *_), _ = env
    path = f"/api/cases/{waiting.id}/decision"
    response, body = call(app, "POST", path, {"action": "modify", "version": "latest"})
    assert response.status == 400
    assert "version=" in body["error"]
    assert "/guardian accept" in body["grammar"]
    # accepted_risk without an expiry
    response, body = call(
        app,
        "POST",
        path,
        {"action": "decline", "decline_reason": "accepted_risk", "justification": "x"},
    )
    assert response.status == 400
    assert "until" in body["error"]
    assert recorder.calls == []


@pytest.mark.parametrize(
    "body",
    [
        {"action": "approve"},
        {"action": "accept", "extra": 1},
        {"action": "accept", "candidate_id": "cand_aaaaaaaaaaaa reason=x"},
        {"action": "modify", "version": 4},
        {"action": "decline", "justification": "x" * 3000},
    ],
)
def test_malformed_form_fields_400(env, body):
    app, recorder, (waiting, *_), _ = env
    response, payload = call(app, "POST", f"/api/cases/{waiting.id}/decision", body)
    assert response.status == 400
    assert payload["error"]
    assert recorder.calls == []


def test_wrong_status_409(env):
    app, recorder, (_, _, verified, declined), _ = env
    response, body = call(app, "POST", f"/api/cases/{declined.id}/decision", {"action": "accept"})
    assert response.status == 409
    assert "CLOSED" in body["error"]
    # revalidate is valid on a verified case
    response, _ = call(app, "POST", f"/api/cases/{verified.id}/decision", {"action": "revalidate"})
    assert response.status == 202
    wait_threads(app)
    assert recorder.calls[0][1].decision is DecisionType.REVALIDATE


def test_unknown_case_decision_404(env):
    app, *_ = env
    response, _ = call(app, "POST", "/api/cases/rc_000000000000/decision", {"action": "accept"})
    assert response.status == 404


def test_second_decision_while_pending_409(env):
    app, _, (waiting, *_), _ = env
    import threading

    gate = threading.Event()

    def slow(case, decision):
        gate.wait(5)

    app.decisions.handler = slow
    path = f"/api/cases/{waiting.id}/decision"
    assert call(app, "POST", path, {"action": "accept"})[0].status == 202
    _, listed = call(app, "GET", "/api/cases")
    pending = next(c for c in listed["cases"] if c["id"] == waiting.id)
    assert pending["decision_pending"] is True
    assert pending["live"] is True
    response, body = call(app, "POST", path, {"action": "accept"})
    assert response.status == 409
    assert "already being processed" in body["error"]
    gate.set()
    wait_threads(app)
    assert app.decisions.pending() == frozenset()


def test_default_handler_moves_case(env):
    app, _, (waiting, *_), settings = env
    app.decisions = DecisionService(settings, user=lambda: "alice")
    response, _ = call(app, "POST", f"/api/cases/{waiting.id}/decision", {"action": "accept"})
    assert response.status == 202
    wait_threads(app)
    with Database(settings.database_path) as db:
        assert db.remediation.get(waiting.id).status is CaseStatus.APPROVED
        assert db.audit.verify() == (True, [])
    _, body = call(app, "GET", f"/api/cases/{waiting.id}")
    stations = {s["key"]: s["state"] for s in body["journey"]["stations"]}
    assert stations["apply"] == "current"
    assert body["journey"]["live"] is True


def test_failing_handler_is_audited(env):
    app, _, (waiting, *_), settings = env

    def boom(case, decision):
        msg = "graph exploded"
        raise RuntimeError(msg)

    app.decisions.handler = boom
    assert (
        call(app, "POST", f"/api/cases/{waiting.id}/decision", {"action": "accept"})[0].status
        == 202
    )
    wait_threads(app)
    with Database(settings.database_path) as db:
        last = db.audit.list(waiting.id)[-1]
    assert last.event == "decision:handler_failed"
    assert "graph exploded" in last.payload_json
    assert app.decisions.pending() == frozenset()


def test_command_line_builder():
    assert command_line({"action": "accept"}) == "/guardian accept"
    assert (
        command_line({"action": "decline", "decline_reason": "WONT_FIX", "justification": " no "})
        == "/guardian decline reason=wont_fix -- no"
    )
    assert (
        command_line({"action": "modify", "version": "1.2.3", "until": None, "justification": ""})
        == "/guardian modify version=1.2.3"
    )

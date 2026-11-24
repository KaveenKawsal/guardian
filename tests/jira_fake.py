"""In-memory Jira Cloud stand-in behind ``httpx.MockTransport`` plus remediation seed data."""

import json
import re
from datetime import UTC, datetime
from urllib.parse import parse_qs

import httpx
from pydantic import SecretStr

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
    RemediationActionType,
    RemediationCandidate,
    RemediationCase,
    RemediationPlan,
    SemverJump,
    candidate_id_for,
    case_id_for,
    fingerprint_for,
)
from guardian.integrations.jira import adf
from guardian.integrations.jira.client import JiraClient

BASE_URL = "https://example.atlassian.net"
EMAIL = "bot@example.com"
TOKEN = "jira-token-SECRET-0123456789"  # noqa: S105 - test fixture
GUARDIAN_ID = "acct-guardian"
APPROVER_ID = "acct-alice"
OUTSIDER_ID = "acct-mallory"
ROOT = "/work/juice-shop"
T0 = datetime(2026, 11, 1, tzinfo=UTC)

_ISSUE_PATH = re.compile(r"^/rest/api/3/issue/([A-Z0-9_]+-\d+)(/comment|/transitions)?$")


class FakeJira:
    def __init__(self, *, time_zone: str = "UTC", page_size: int = 50) -> None:
        self.issues: dict[str, dict] = {}
        self.comments: dict[str, list[dict]] = {}
        self.requests: list[httpx.Request] = []
        self.queued: list[httpx.Response] = []
        self.sleeps: list[float] = []
        self.jql: list[str] = []
        self.transitions: list[dict] = [{"id": "31", "name": "Done", "to": {"name": "Done"}}]
        self.transitioned: list[tuple[str, str]] = []
        self.reject_priority = False
        self.time_zone = time_zone
        self.page_size = page_size
        self._next_issue = 1
        self._next_comment = 10_000

    # --- client -----------------------------------------------------------------------

    def client(self, **kwargs) -> JiraClient:
        http = httpx.Client(transport=httpx.MockTransport(self.handler))
        return JiraClient(
            BASE_URL, EMAIL, SecretStr(TOKEN), http, sleep=self.sleeps.append, **kwargs
        )

    # --- helpers for tests ------------------------------------------------------------

    def add_issue(self, labels: list[str], summary: str = "existing") -> str:
        key = f"SEC-{self._next_issue}"
        self._next_issue += 1
        self.issues[key] = {"summary": summary, "labels": labels}
        self.comments[key] = []
        return key

    def add_comment(self, key: str, author_id: str, body: object, display: str = "Alice") -> str:
        comment_id = str(self._next_comment)
        self._next_comment += 1
        if isinstance(body, str):
            body = adf.doc(*(adf.paragraph(line) for line in body.split("\n") if line))
        self.comments.setdefault(key, []).append(
            {
                "id": comment_id,
                "author": {"accountId": author_id, "displayName": display},
                "body": body,
                "created": "2026-11-24T10:00:00.000+0000",
            }
        )
        return comment_id

    def guardian_replies(self, key: str) -> list[str]:
        return [
            adf.adf_to_text(c["body"])
            for c in self.comments.get(key, [])
            if c["author"]["accountId"] == GUARDIAN_ID
        ]

    def calls(self, method: str, path_prefix: str) -> list[httpx.Request]:
        return [
            r for r in self.requests if r.method == method and r.url.path.startswith(path_prefix)
        ]

    # --- transport --------------------------------------------------------------------

    def handler(self, request: httpx.Request) -> httpx.Response:  # noqa: C901, PLR0911, PLR0912
        self.requests.append(request)
        if self.queued:
            return self.queued.pop(0)
        path = request.url.path
        body = json.loads(request.content) if request.content else {}
        if path == "/rest/api/3/myself":
            return httpx.Response(
                200,
                json={
                    "accountId": GUARDIAN_ID,
                    "displayName": "Guardian Bot",
                    "timeZone": self.time_zone,
                },
            )
        if path == "/rest/api/3/search/jql" and request.method == "POST":
            return self._search(body)
        if path == "/rest/api/3/issue" and request.method == "POST":
            fields = body["fields"]
            if self.reject_priority and "priority" in fields:
                return httpx.Response(
                    400, json={"errorMessages": [], "errors": {"priority": "cannot be set"}}
                )
            key = self.add_issue(fields["labels"], fields["summary"])
            self.issues[key] = dict(fields)
            return httpx.Response(201, json={"id": "1", "key": key})
        match = _ISSUE_PATH.match(path)
        if match is None:
            return httpx.Response(404, json={"errorMessages": ["no route"]})
        key, sub = match.groups()
        if key not in self.issues:
            return httpx.Response(404, json={"errorMessages": ["Issue does not exist"]})
        if sub is None and request.method == "PUT":
            if self.reject_priority and "priority" in body["fields"]:
                return httpx.Response(400, json={"errors": {"priority": "cannot be set"}})
            self.issues[key].update(body["fields"])
            return httpx.Response(204)
        if sub is None and request.method == "GET":
            return httpx.Response(200, json={"key": key, "fields": self.issues[key]})
        if sub == "/comment" and request.method == "GET":
            return self._comments(key, request)
        if sub == "/comment" and request.method == "POST":
            comment_id = self.add_comment(key, GUARDIAN_ID, body["body"], "Guardian Bot")
            return httpx.Response(201, json={"id": comment_id})
        if sub == "/transitions" and request.method == "GET":
            return httpx.Response(200, json={"transitions": self.transitions})
        if sub == "/transitions" and request.method == "POST":
            self.transitioned.append((key, body["transition"]["id"]))
            return httpx.Response(204)
        return httpx.Response(405)

    def _search(self, body: dict) -> httpx.Response:
        jql = body["jql"]
        self.jql.append(jql)
        label = re.search(r'labels = "([^"]+)"', jql)
        wanted = label.group(1) if label else "guardian"
        keys = [k for k, v in self.issues.items() if wanted in v.get("labels", [])]
        start = int(body.get("nextPageToken") or 0)
        page = keys[start : start + self.page_size]
        result: dict = {"issues": [{"id": k, "key": k, "fields": {}} for k in page]}
        if start + self.page_size < len(keys):
            result["nextPageToken"] = str(start + self.page_size)
        return httpx.Response(200, json=result)

    def _comments(self, key: str, request: httpx.Request) -> httpx.Response:
        query = parse_qs(request.url.query.decode())
        start = int(query.get("startAt", ["0"])[0])
        size = min(int(query.get("maxResults", ["50"])[0]), self.page_size)
        items = self.comments.get(key)
        if items is None:
            return httpx.Response(500, json={"errorMessages": ["comments unavailable"]})
        return httpx.Response(
            200,
            json={
                "startAt": start,
                "maxResults": size,
                "total": len(items),
                "comments": items[start : start + size],
            },
        )


# --- settings and seed data -----------------------------------------------------------------


def jira_settings(tmp_path, **overrides) -> GuardianSettings:
    values = {
        "data_dir": tmp_path / "data",
        "jira_base_url": BASE_URL,
        "jira_email": EMAIL,
        "jira_api_token": TOKEN,
        "jira_project_key": "SEC",
        "approvers": [APPROVER_ID],
        "cli_approvers": ["alice"],
    }
    values.update(overrides)
    return GuardianSettings(_env_file=None, **values)


def seed_scan(db, scan_id: str = "scan-1") -> str:
    repo_id = db.repositories.upsert(ROOT, "juice-shop")
    profile = RepositoryProfile(
        name="juice-shop",
        root=ROOT,
        profiled_at=T0,
        total_files=1,
        total_bytes=1,
        git=GitInfo(is_repository=True),
    )
    db.scans.create(scan_id, repo_id, T0, profile)
    return scan_id


def vuln_finding(package: str = "jsonwebtoken", version: str = "0.4.0") -> Finding:
    return Finding(
        id=f"vuln-{package}-{version}",
        kind=FindingKind.VULNERABILITY,
        title=f"{package} {version}: verification bypass",
        severity=Severity.HIGH,
        tool="osv-scanner",
        component_ref=f"pkg:npm/{package}@{version}",
        details=VulnerabilityDetails(
            vulnerability_id="GHSA-c7hr-j4mj-j2w6",
            aliases=["CVE-2015-9235"],
            summary="Verification bypass in jsonwebtoken",
            package=package,
            version=version,
            ecosystem="npm",
            purl=f"pkg:npm/{package}@{version}",
            fixed_versions=["4.2.2"],
        ),
        evidence=[
            Evidence(
                kind=EvidenceKind.ADVISORY,
                tool="osv-scanner",
                summary="GHSA-c7hr-j4mj-j2w6 affects jsonwebtoken < 4.2.2",
                url="https://osv.dev/GHSA-c7hr-j4mj-j2w6",
            ),
            Evidence(
                kind=EvidenceKind.MANIFEST,
                tool="guardian",
                summary="declared in package.json",
                path="package.json",
                line=12,
            ),
        ],
    )


def assessment(finding: Finding, priority: Priority = Priority.P2) -> RiskAssessment:
    return RiskAssessment(
        finding_id=finding.id,
        score=72.5,
        known_weight=0.8,
        confidence=Confidence.MEDIUM,
        priority=priority,
        factors=[
            RiskFactor(name=RiskFactorName.SEVERITY, weight=0.35, value=0.8, rationale="HIGH"),
            RiskFactor(
                name=RiskFactorName.EXPLOITABILITY, weight=0.2, value=None, rationale="no data"
            ),
        ],
        summary="P2 because severity is high",
    )


def seed_case(
    db,
    *,
    scan_id: str = "scan-1",
    package: str = "jsonwebtoken",
    version: str = "0.4.0",
    priority: Priority = Priority.P2,
    status: CaseStatus = CaseStatus.AWAITING_DECISION,
    created_at: datetime = T0,
    inferred: bool = False,
):
    """Create a case (moved to ``status`` along legal edges) with two candidates and a plan."""
    finding = vuln_finding(package, version)
    fp = fingerprint_for(ROOT, f"pkg:npm/{package}@{version}", "GHSA-c7hr-j4mj-j2w6")
    case = RemediationCase(
        id=case_id_for(fp),
        fingerprint=fp,
        scan_id=scan_id,
        repository_root=ROOT,
        finding_ids=[finding.id],
        title=f"{package} {version}",
        priority=priority,
        created_at=created_at,
        updated_at=created_at,
    )
    db.remediation.create(case)
    path = {
        CaseStatus.PROPOSED: [],
        CaseStatus.AWAITING_DECISION: [CaseStatus.AWAITING_DECISION],
        CaseStatus.VALIDATION_FAILED: [
            CaseStatus.AWAITING_DECISION,
            CaseStatus.APPROVED,
            CaseStatus.APPLYING,
            CaseStatus.VALIDATION_FAILED,
        ],
        CaseStatus.CLOSED: [CaseStatus.AWAITING_DECISION, CaseStatus.DECLINED, CaseStatus.CLOSED],
    }[status]
    for step in path:
        case = db.remediation.update_status(case.id, step)
    candidates = [
        RemediationCandidate(
            id=candidate_id_for(fp, RemediationActionType.UPGRADE, f"pkg:npm/{package}", to),
            case_id=case.id,
            finding_ids=[finding.id],
            action_type=RemediationActionType.UPGRADE,
            component=f"pkg:npm/{package}",
            from_version=version,
            to_version=to,
            manifest_path="package.json",
            fixes_finding_ids=[finding.id],
            semver_jump=SemverJump.MAJOR,
            compatibility_notes=["major version bump 0.x -> 4.x"],
            rollback="git revert <commit>",
            expected_risk_reduction=72.5,
        )
        for to in ("4.2.2", "9.0.0")
    ]
    db.remediation.save_candidates(case.id, candidates)
    plan = RemediationPlan(
        case_id=case.id,
        chosen_candidate_id=candidates[0].id,
        alternatives=[candidates[1].id],
        rationale="Lowest fixed version.",
        confidence=Confidence.MEDIUM,
        source="inferred" if inferred else "verified",
        decided_by="llm" if inferred else "deterministic",
        llm_provider="groq" if inferred else None,
        llm_model="gpt-oss" if inferred else None,
    )
    db.remediation.save_plan(plan)
    return case, finding, assessment(finding, priority), candidates, plan

import sqlite3
from datetime import UTC, datetime, timedelta
from importlib.resources import files

import pytest

from guardian.core.models import (
    ChangeCategory,
    ChangeDetails,
    ChangeRecord,
    CodeDetails,
    Evidence,
    EvidenceKind,
    FileChange,
    Finding,
    FindingKind,
    GitInfo,
    RepositoryProfile,
    ScanStatus,
    Severity,
    VulnerabilityDetails,
)
from guardian.storage.database import SCHEMA_VERSION, Database
from guardian.storage.findings import FindingNotFoundError

T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _profile():
    return RepositoryProfile(
        name="app",
        root="/work/app",
        profiled_at=T0,
        total_files=1,
        total_bytes=1,
        git=GitInfo(is_repository=False),
    )


def _findings():
    return [
        Finding(
            id="aaaa0001",
            kind=FindingKind.VULNERABILITY,
            title="CVE-1 in x@1",
            severity=Severity.HIGH,
            tool="osv-scanner",
            component_ref="pkg:npm/x@1",
            details=VulnerabilityDetails(vulnerability_id="CVE-1", package="x", version="1"),
            evidence=[
                Evidence(
                    kind=EvidenceKind.ADVISORY,
                    tool="osv-scanner",
                    summary="s",
                    url="https://osv.dev/x",
                )
            ],
        ),
        Finding(
            id="aaaa0002",
            kind=FindingKind.CODE,
            title="rule in a.py:1",
            severity=Severity.MEDIUM,
            tool="semgrep",
            path="a.py",
            start_line=1,
            introduced_by="c" * 40,
            details=CodeDetails(rule_id="rule", message="m", cwe_ids=["CWE-78"]),
        ),
        Finding(
            id="bbbb0003",
            kind=FindingKind.CHANGE,
            title="CI changed",
            severity=Severity.INFO,
            tool="git",
            details=ChangeDetails(
                category=ChangeCategory.CI_CONFIG, commit="c" * 40, paths=["ci.yml"]
            ),
        ),
    ]


@pytest.fixture
def db(tmp_path):
    with Database(tmp_path / "g.db") as database:
        yield database


def _scan(db, scan_id, started):
    repo = db.repositories.upsert("/work/app", "app")
    db.scans.create(scan_id, repo, started, _profile())


def test_round_trip_and_filters(db):
    _scan(db, "s1", T0)
    change = ChangeRecord(
        commit="c" * 40, author="Dev", files=[FileChange(path="ci.yml", status="M")]
    )
    db.findings.save("s1", _findings(), [change, change])  # duplicate commits are ignored

    loaded = db.findings.load("s1")
    assert loaded == sorted(_findings(), key=lambda f: -f.severity.rank)
    assert [f.id for f in db.findings.load("s1", min_severity=Severity.MEDIUM)] == [
        "aaaa0001",
        "aaaa0002",
    ]
    assert [f.id for f in db.findings.load("s1", kind=FindingKind.CHANGE)] == ["bbbb0003"]
    assert db.findings.changes("s1") == [change]


def test_get_by_prefix(db):
    _scan(db, "s1", T0)
    db.findings.save("s1", _findings(), [])
    assert db.findings.get("s1", "bbbb").id == "bbbb0003"
    with pytest.raises(FindingNotFoundError, match="ambiguous"):
        db.findings.get("s1", "aaaa")
    with pytest.raises(FindingNotFoundError):
        db.findings.get("s1", "zzz")
    with pytest.raises(FindingNotFoundError):
        db.findings.get("s1", "_")  # LIKE wildcard escaped


def test_scans_containing_tracks_persistence(db):
    _scan(db, "s1", T0)
    _scan(db, "s2", T0 + timedelta(days=1))
    db.findings.save("s1", _findings(), [])
    db.findings.save("s2", _findings()[:1], [])
    assert db.findings.scans_containing("aaaa0001") == ["s2", "s1"]
    assert db.findings.scans_containing("bbbb0003") == ["s1"]


def test_finding_count_recorded(db):
    _scan(db, "s1", T0)
    db.scans.finish(
        "s1",
        status=ScanStatus.COMPLETED,
        finished_at=T0,
        tool_runs=[],
        warnings=[],
        component_count=0,
        finding_count=3,
    )
    assert db.scans.get("s1").finding_count == 3


def test_upgrades_a_version_1_database(tmp_path):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    v1 = files("guardian.storage").joinpath("migrations", "001_initial.sql").read_text("utf-8")
    conn.executescript(
        v1
        + "\nCREATE TABLE schema_version (version INTEGER); INSERT INTO schema_version VALUES (1);"
    )
    conn.execute("INSERT INTO repositories (root_path, name, created_at) VALUES ('/r', 'r', 'x')")
    conn.execute(
        "INSERT INTO scans (id, repository_id, status, started_at) VALUES ('old', 1, 'completed', '2026-01-01T00:00:00+00:00')"
    )
    conn.commit()
    conn.close()

    with Database(path) as db:
        version = db.conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
        assert version == SCHEMA_VERSION == 3  # v1 -> v2 -> v3 in place
        record = db.scans.get("old")  # phase 2 scans stay readable
        assert record.finding_count == 0
        assert db.findings.load("old") == []

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from guardian.analysis.cyclonedx import parse_cyclonedx
from guardian.core.models import GitInfo, RepositoryProfile, ScanStatus, ToolRunSummary
from guardian.storage.database import SCHEMA_VERSION, Database, StorageError
from guardian.storage.scans import ScanNotFoundError

FIXTURES = Path(__file__).parents[1] / "fixtures" / "sbom"
T0 = datetime(2026, 1, 1, tzinfo=UTC)


@pytest.fixture
def db(tmp_path):
    with Database(tmp_path / "data" / "guardian.db") as database:
        yield database


def _profile(name="app", root="/work/app", commit="abc123"):
    return RepositoryProfile(
        name=name,
        root=root,
        profiled_at=T0,
        total_files=1,
        total_bytes=1,
        git=GitInfo(is_repository=True, branch="main", head_commit=commit),
    )


def _scan(db, scan_id, started=T0, root="/work/app"):
    repo_id = db.repositories.upsert(root, Path(root).name)
    db.scans.create(scan_id, repo_id, started, _profile(root=root))
    return repo_id


def test_repository_upsert_is_idempotent(db):
    first = db.repositories.upsert("/work/app", "app")
    assert db.repositories.upsert("/work/app", "renamed") == first
    assert db.repositories.find_id("/work/app") == first
    assert db.repositories.find_id("/elsewhere") is None


def test_scan_lifecycle(db):
    _scan(db, "aaaa1111")
    assert db.scans.get("aaaa1111").status is ScanStatus.RUNNING
    db.scans.finish(
        "aaaa1111",
        status=ScanStatus.PARTIAL,
        finished_at=T0 + timedelta(seconds=5),
        tool_runs=[ToolRunSummary(tool="cdxgen", status="not_found", error="missing")],
        warnings=["something"],
        component_count=7,
    )
    record = db.scans.get("aaaa1111")
    assert record.status is ScanStatus.PARTIAL
    assert record.git_commit == "abc123"
    assert record.component_count == 7
    assert record.tool_runs[0].tool == "cdxgen"
    assert record.warnings == ["something"]
    assert db.scans.profile("aaaa1111") == _profile()


def test_resolve(db):
    _scan(db, "abc111", started=T0)
    _scan(db, "abc222", started=T0 + timedelta(minutes=1))
    _scan(db, "zzz333", started=T0 + timedelta(minutes=2), root="/work/other")
    assert db.scans.resolve("zzz") == "zzz333"
    assert db.scans.resolve("abc111") == "abc111"
    assert db.scans.resolve("latest") == "zzz333"
    assert db.scans.resolve("latest", repository_root="/work/app") == "abc222"
    with pytest.raises(ScanNotFoundError, match="ambiguous"):
        db.scans.resolve("abc")
    with pytest.raises(ScanNotFoundError):
        db.scans.resolve("nope")
    with pytest.raises(ScanNotFoundError):
        db.scans.resolve("%")  # LIKE wildcards are escaped
    with pytest.raises(ScanNotFoundError):
        db.scans.get("nope")
    with pytest.raises(ScanNotFoundError):
        db.scans.profile("nope")


def test_resolve_latest_with_no_scans(db):
    with pytest.raises(ScanNotFoundError):
        db.scans.resolve("latest")


def test_recent_filters_and_orders(db):
    _scan(db, "s1", started=T0)
    _scan(db, "s2", started=T0 + timedelta(minutes=1))
    _scan(db, "s3", started=T0 + timedelta(minutes=2), root="/work/other")
    assert [r.id for r in db.scans.recent()] == ["s3", "s2", "s1"]
    assert [r.id for r in db.scans.recent("/work/app")] == ["s2", "s1"]
    assert [r.id for r in db.scans.recent(limit=1)] == ["s3"]


def test_sbom_round_trip(db):
    _scan(db, "s1")
    raw = (FIXTURES / "node-express.cdx.json").read_bytes()
    sbom = parse_cyclonedx(raw, repo_root=Path("/work/app"), manifests=set())
    db.sboms.save("s1", sbom, raw)
    assert db.sboms.load("s1") == sbom
    assert db.sboms.raw("s1") == raw
    assert db.sboms.load("missing") is None
    assert db.sboms.raw("missing") is None


def test_reopening_keeps_data_and_rejects_newer_schema(tmp_path):
    path = tmp_path / "guardian.db"
    with Database(path) as first:
        _scan(first, "s1")
    with Database(path) as second:
        assert second.scans.get("s1").id == "s1"
        second.conn.execute("INSERT INTO schema_version VALUES (?)", (SCHEMA_VERSION + 1,))
        second.conn.commit()
    with pytest.raises(StorageError, match="Upgrade Guardian"):
        Database(path)

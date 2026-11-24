"""Migration 006 and InvestigationStore."""

from datetime import UTC, datetime, timedelta

from guardian.core.models import GitInfo, RepositoryProfile
from guardian.investigation.models import (
    CallRecord,
    Fact,
    InvestigationRun,
    InvestigatorReport,
    TraceEvent,
)
from guardian.storage.database import MIGRATIONS, SCHEMA_VERSION, Database

T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _scan(db, scan_id="s1"):
    repo = db.repositories.upsert("/r", "r")
    profile = RepositoryProfile(
        name="r",
        root="/r",
        profiled_at=T0,
        total_files=1,
        total_bytes=1,
        git=GitInfo(is_repository=True),
    )
    db.scans.create(scan_id, repo, T0, profile)


def _run(run_id, at, status="completed"):
    return InvestigationRun(
        id=run_id,
        scan_id="s1",
        started_at=at,
        finished_at=at + timedelta(seconds=3),
        status=status,
        max_calls=40,
        provider_calls=[
            CallRecord(
                agent="code",
                subject_id="f1",
                role="fast",
                provider="groq",
                model="m",
                latency_seconds=1.5,
                input_tokens=10,
                output_tokens=5,
            )
        ],
        trace=[
            TraceEvent(
                node="code", event="finished", at=at, agent="code", subject_id="f1", status="ok"
            )
        ],
        notes=["n1"],
    )


def _report(agent, subject, kind="finding", status="ok"):
    return InvestigatorReport(
        agent=agent,
        subject_kind=kind,
        subject_id=subject,
        status=status,
        source="inferred" if status != "ai_unavailable" else "verified",
        verified_facts=[Fact(label="Rule", value="sqli", ref=subject)],
        assessment={"source": "inferred"} if status != "ai_unavailable" else None,
    )


def test_migration_006_tables(tmp_path):
    assert MIGRATIONS[6] == "006_investigations.sql"
    assert SCHEMA_VERSION >= 6
    with Database(tmp_path / "g.db") as db:
        tables = {
            r[0] for r in db.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert {"investigation_runs", "investigation_reports"} <= tables
        version = db.conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
        assert version == SCHEMA_VERSION


def test_roundtrip_latest_and_filter(tmp_path):
    with Database(tmp_path / "g.db") as db:
        _scan(db)
        store = db.investigations
        assert store.latest_run("s1") is None
        store.save_run(_run("ir_old", T0), [_report("code", "f1")])
        reports = [
            _report("architect", "s1", "scan"),
            _report("code", "f1"),
            _report("correlator", "f1", status="ai_unavailable"),
        ]
        store.save_run(_run("ir_new", T0 + timedelta(hours=1), "partial"), reports)
        latest = store.latest_run("s1")
        assert latest.id == "ir_new"
        assert latest.status == "partial"
        assert latest.max_calls == 40
        assert latest.notes == ["n1"]
        assert latest.provider_calls[0].input_tokens == 10
        assert latest.trace[0].agent == "code"
        assert [r.agent for r in store.reports("ir_new")] == ["architect", "code", "correlator"]
        assert [r.agent for r in store.reports("ir_new", "f1")] == ["code", "correlator"]
        assert store.reports("ir_new", "f1")[1].source == "verified"
        assert store.get_run("ir_old").id == "ir_old"
        assert store.get_run("missing") is None
        assert store.count_runs() == 2
        # saving the same run again replaces its reports (idempotent persist)
        store.save_run(_run("ir_new", T0 + timedelta(hours=1)), [_report("code", "f1")])
        assert len(store.reports("ir_new")) == 1
        row = db.conn.execute(
            "SELECT source FROM investigation_reports WHERE run_id='ir_new'"
        ).fetchone()
        assert row["source"] == "inferred"

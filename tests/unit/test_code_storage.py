import sqlite3
from datetime import UTC, datetime
from importlib.resources import files

from guardian.core.models import (
    CodeIndex,
    EntryPoint,
    EntryPointKind,
    FileIndex,
    GitInfo,
    ImportStyle,
    ImportTarget,
    RepositoryProfile,
    ResolvedImport,
    SourceLanguage,
    Span,
    Symbol,
    SymbolKind,
)
from guardian.indexing import tree_sitter
from guardian.storage.code_index import SqliteIndexCache
from guardian.storage.database import SCHEMA_VERSION, Database

T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _scan(db, scan_id="s1"):
    repo_id = db.repositories.upsert("/work/app", "app")
    profile = RepositoryProfile(
        name="app",
        root="/work/app",
        profiled_at=T0,
        total_files=1,
        total_bytes=1,
        git=GitInfo(is_repository=False),
    )
    db.scans.create(scan_id, repo_id, T0, profile)


def _fi(path="app.py", sha="h1"):
    sym = Symbol(
        id=f"{path}::main",
        name="main",
        qualified_name="main",
        kind=SymbolKind.FUNCTION,
        path=path,
        span=Span(start_line=1, end_line=2),
    )
    return FileIndex(
        path=path,
        language=SourceLanguage.PYTHON,
        sha256=sha,
        size=10,
        line_count=2,
        symbols=[sym],
    )


def _index():
    return CodeIndex(
        files=[_fi()],
        imports=[
            ResolvedImport(
                path="app.py",
                line=1,
                module="os",
                style=ImportStyle.IMPORT,
                target=ImportTarget.STDLIB,
                package="os",
            )
        ],
        entry_points=[EntryPoint(path="app.py", kind=EntryPointKind.MAIN_GUARD, detail="x")],
        skipped_files={"minified": 2},
        warnings=["w"],
    )


def test_code_index_round_trip(tmp_path):
    with Database(tmp_path / "g.db") as db:
        _scan(db)
        assert db.code.load("s1") is None
        db.code.save("s1", _index())
        assert db.code.load("s1") == _index()
        row = db.conn.execute("SELECT * FROM code_indexes WHERE scan_id = 's1'").fetchone()
        assert (row["file_count"], row["symbol_count"], row["import_count"], row["call_count"]) == (
            1,
            1,
            1,
            0,
        )
        db.conn.execute("DELETE FROM scans WHERE id = 's1'")  # cascades
        assert db.code.load("s1") is None


def test_sqlite_cache_round_trip_and_buffering(tmp_path):
    path = tmp_path / "g.db"
    with Database(path) as db:
        cache = db.code.cache()
        cache.put(_fi())
        assert cache.get("app.py", "h1", SourceLanguage.PYTHON) == _fi()  # served from buffer
        assert db.conn.execute("SELECT COUNT(*) FROM file_index_cache").fetchone()[0] == 0
        cache.flush()
        assert db.conn.execute("SELECT COUNT(*) FROM file_index_cache").fetchone()[0] == 1
    with Database(path) as db:
        cache = SqliteIndexCache(db)
        assert cache.get("app.py", "h1", SourceLanguage.PYTHON) == _fi()
        assert cache.get("app.py", "other", SourceLanguage.PYTHON) is None
        assert cache.get("app.py", "h1", SourceLanguage.TYPESCRIPT) is None


def test_sqlite_cache_invalidated_by_extractor_version(tmp_path, monkeypatch):
    with Database(tmp_path / "g.db") as db:
        cache = db.code.cache()
        cache.put(_fi())
        cache.flush()
        monkeypatch.setattr(tree_sitter, "EXTRACTOR_VERSION", "999")
        assert db.code.cache().get("app.py", "h1", SourceLanguage.PYTHON) is None


def test_sqlite_cache_ignores_corrupt_rows(tmp_path):
    with Database(tmp_path / "g.db") as db:
        db.conn.execute(
            "INSERT INTO file_index_cache VALUES ('app.py', 'h1', 'python', ?, ?)",
            (tree_sitter.EXTRACTOR_VERSION, b"not zlib"),
        )
        assert db.code.cache().get("app.py", "h1", SourceLanguage.PYTHON) is None


def test_upgrades_a_version_2_database(tmp_path):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    for name in ("001_initial.sql", "002_findings.sql"):
        conn.executescript(
            files("guardian.storage").joinpath("migrations", name).read_text("utf-8")
        )
    conn.executescript(
        "CREATE TABLE schema_version (version INTEGER);"
        "INSERT INTO schema_version VALUES (1); INSERT INTO schema_version VALUES (2);"
    )
    conn.execute("INSERT INTO repositories (root_path, name, created_at) VALUES ('/r', 'r', 'x')")
    conn.execute(
        "INSERT INTO scans (id, repository_id, status, started_at) VALUES ('old', 1, 'completed', '2026-01-01T00:00:00+00:00')"
    )
    conn.commit()
    conn.close()

    with Database(path) as db:
        assert (
            db.conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
            == SCHEMA_VERSION
        )
        assert db.scans.get("old") is not None
        assert db.findings.load("old") == []
        assert db.code.load("old") is None
        db.code.save("old", _index())
        assert db.code.load("old") == _index()

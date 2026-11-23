"""SQLite connection management and schema migration."""

import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from importlib.resources import files
from pathlib import Path
from types import TracebackType
from typing import Self

from guardian.core.exceptions import GuardianError

MIGRATIONS: dict[int, str] = {
    1: "001_initial.sql",
    2: "002_findings.sql",
    3: "003_code_index.sql",
}
SCHEMA_VERSION = max(MIGRATIONS)


class StorageError(GuardianError):
    """The Guardian database is missing, corrupt or from an incompatible version."""


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self._migrate()

        from guardian.storage.code_index import CodeIndexStore  # noqa: PLC0415
        from guardian.storage.findings import FindingStore  # noqa: PLC0415
        from guardian.storage.repositories import RepositoryStore  # noqa: PLC0415
        from guardian.storage.sboms import SbomStore  # noqa: PLC0415
        from guardian.storage.scans import ScanStore  # noqa: PLC0415

        self.repositories = RepositoryStore(self)
        self.scans = ScanStore(self)
        self.sboms = SbomStore(self)
        self.findings = FindingStore(self)
        self.code = CodeIndexStore(self)

    def _migrate(self) -> None:
        with self.conn:
            self.conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER)")
            row = self.conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
            current = row[0] or 0
            if current > SCHEMA_VERSION:
                msg = (
                    f"Database {self.path} uses schema v{current}; this Guardian supports "
                    f"up to v{SCHEMA_VERSION}. Upgrade Guardian."
                )
                raise StorageError(msg)
            for version, filename in MIGRATIONS.items():
                if version <= current:
                    continue
                script = files("guardian.storage").joinpath("migrations", filename)
                # One script per migration so it and its version row commit atomically.
                self.conn.executescript(
                    f"BEGIN;\n{script.read_text('utf-8')}\n"
                    f"INSERT INTO schema_version VALUES ({version:d});\nCOMMIT;"
                )

    @contextmanager
    def transaction(self) -> Generator[sqlite3.Connection]:
        """Commit on success, roll back on error."""
        with self.conn:
            yield self.conn

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

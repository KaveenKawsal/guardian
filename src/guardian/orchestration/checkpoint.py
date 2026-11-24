"""Durable LangGraph checkpoints in SQLite.

Pending approvals must survive a restart, so the remediation graph always runs with this
checkpointer (``InMemorySaver`` would lose them). The default location is
``<data_dir>/checkpoints.sqlite``; callers pass the path in.
"""

import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from langgraph.checkpoint.sqlite import SqliteSaver

CHECKPOINTS_FILENAME = "checkpoints.sqlite"


def checkpoint_path(data_dir: Path) -> Path:
    return data_dir / CHECKPOINTS_FILENAME


@contextmanager
def open_checkpointer(path: Path) -> Generator[SqliteSaver]:
    """Open (creating if needed) the checkpoint database at ``path``; close it on exit.

    ``check_same_thread=False`` is what ``SqliteSaver.from_conn_string`` uses too: the saver
    serialises access with its own lock, and LangGraph may write checkpoints from a worker thread.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    try:
        saver = SqliteSaver(conn)
        saver.setup()
        yield saver
    finally:
        conn.close()

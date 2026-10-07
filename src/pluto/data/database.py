"""Database connection management.

A single :class:`Database` owns the SQLite file. Connections are per-thread
(SQLite objects are not shareable across threads) and configured for
durability and foreign-key enforcement, which SQLite leaves off by default.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from pluto.core.exceptions import StorageError
from pluto.core.logging_config import get_logger
from pluto.data.schema import CURRENT_VERSION, apply_migrations, get_user_version

log = get_logger("data.database")


def _configure(conn: sqlite3.Connection) -> None:
    """Pragmas applied to every connection."""
    conn.row_factory = sqlite3.Row
    # Autocommit mode: transactions are opened explicitly by transaction().
    # Without this, Python's sqlite3 opens an implicit transaction before our
    # BEGIN IMMEDIATE and the nested BEGIN fails. Set on every connection so
    # in-memory and on-disk databases behave identically.
    conn.isolation_level = None
    # WAL lets the UI read while a task writes.
    conn.execute("PRAGMA journal_mode = WAL;")
    # FULL would be slower; NORMAL is durable enough with WAL.
    conn.execute("PRAGMA synchronous = NORMAL;")
    # Off by default in SQLite — without this, ON DELETE CASCADE is a no-op.
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA busy_timeout = 5000;")
    conn.execute("PRAGMA temp_store = MEMORY;")


class Database:
    """Owns the SQLite file and hands out per-thread connections."""

    def __init__(self, path: Path | str, *, create_parents: bool = True) -> None:
        self._path = Path(path)
        self._is_memory = str(path) == ":memory:"
        if create_parents and not self._is_memory:
            self._path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._shared_memory_conn: sqlite3.Connection | None = None
        self._lock = threading.Lock()
        self._migrated = False

    @property
    def path(self) -> Path:
        return self._path

    # -- connections ------------------------------------------------------
    def connect(self) -> sqlite3.Connection:
        """Connection for the calling thread, created on first use."""
        if self._is_memory:
            # An in-memory database vanishes with its connection, so tests get
            # one shared connection instead of one per thread.
            with self._lock:
                if self._shared_memory_conn is None:
                    conn = sqlite3.connect(":memory:", check_same_thread=False)
                    _configure(conn)
                    self._shared_memory_conn = conn
                return self._shared_memory_conn

        conn: sqlite3.Connection | None = getattr(self._local, "conn", None)
        if conn is None:
            try:
                conn = sqlite3.connect(
                    self._path, timeout=10.0, isolation_level=None
                )
            except sqlite3.Error as exc:
                raise StorageError(
                    f"Cannot open database at {self._path}: {exc}",
                    user_message=(
                        "Pluto could not open its local database. Check that "
                        "the data folder is writable."
                    ),
                ) from exc
            _configure(conn)
            self._local.conn = conn
        return conn

    def close(self) -> None:
        """Close this thread's connection (and the shared in-memory one)."""
        conn: sqlite3.Connection | None = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None
        with self._lock:
            if self._shared_memory_conn is not None:
                self._shared_memory_conn.close()
                self._shared_memory_conn = None

    # -- migrations -------------------------------------------------------
    def initialise(self) -> int:
        """Apply pending migrations. Safe to call repeatedly."""
        conn = self.connect()
        version = apply_migrations(conn)
        self._migrated = True
        log.info("Database ready at schema version %s", version)
        return version

    @property
    def schema_version(self) -> int:
        return get_user_version(self.connect())

    @property
    def is_current(self) -> bool:
        return self.schema_version == CURRENT_VERSION

    # -- queries ----------------------------------------------------------
    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Explicit transaction. Commits on success, rolls back on error."""
        conn = self.connect()
        conn.execute("BEGIN IMMEDIATE;")
        try:
            yield conn
        except Exception:
            conn.execute("ROLLBACK;")
            raise
        else:
            conn.execute("COMMIT;")

    def execute(self, sql: str, params: tuple[Any, ...] | dict[str, Any] = ()) -> sqlite3.Cursor:
        try:
            return self.connect().execute(sql, params)
        except sqlite3.Error as exc:
            raise StorageError(
                f"Query failed: {exc}",
                user_message="Pluto could not read or write its local data.",
                detail=sql.strip().split("\n")[0][:200],
            ) from exc

    def executemany(
        self, sql: str, seq: list[tuple[Any, ...]] | list[dict[str, Any]]
    ) -> sqlite3.Cursor:
        try:
            return self.connect().executemany(sql, seq)
        except sqlite3.Error as exc:
            raise StorageError(
                f"Bulk query failed: {exc}",
                user_message="Pluto could not save a batch of records.",
            ) from exc

    def fetch_one(
        self, sql: str, params: tuple[Any, ...] | dict[str, Any] = ()
    ) -> sqlite3.Row | None:
        return self.execute(sql, params).fetchone()

    def fetch_all(
        self, sql: str, params: tuple[Any, ...] | dict[str, Any] = ()
    ) -> list[sqlite3.Row]:
        return self.execute(sql, params).fetchall()

    def fetch_value(
        self, sql: str, params: tuple[Any, ...] | dict[str, Any] = (), default: Any = None
    ) -> Any:
        row = self.fetch_one(sql, params)
        return row[0] if row is not None else default

    # -- maintenance ------------------------------------------------------
    def vacuum(self) -> None:
        self.connect().execute("VACUUM;")

    def table_names(self) -> list[str]:
        rows = self.fetch_all(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name;"
        )
        return [r["name"] for r in rows]

    def row_counts(self) -> dict[str, int]:
        """Record count per table, for the diagnostics screen."""
        counts: dict[str, int] = {}
        for name in self.table_names():
            # Table names come from sqlite_master, not from user input.
            counts[name] = int(self.fetch_value(f"SELECT COUNT(*) FROM {name};", default=0))
        return counts

    def size_bytes(self) -> int:
        if self._is_memory:
            page_size = int(self.fetch_value("PRAGMA page_size;", default=0))
            page_count = int(self.fetch_value("PRAGMA page_count;", default=0))
            return page_size * page_count
        return self._path.stat().st_size if self._path.exists() else 0

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"Database({self._path}, v{self.schema_version})"

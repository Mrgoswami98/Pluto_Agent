"""SQLite schema and migrations.

The schema is versioned through ``PRAGMA user_version``. Each migration is an
idempotent step applied inside a transaction; a failure rolls the whole step
back, so the database is never left half-upgraded.

Adding a migration: append to :data:`MIGRATIONS`. Never edit a released one —
users already have it applied.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass

from pluto.core.exceptions import MigrationError
from pluto.core.logging_config import get_logger

log = get_logger("data.schema")


@dataclass(frozen=True)
class Migration:
    version: int
    description: str
    statements: tuple[str, ...] = ()
    callable_step: Callable[[sqlite3.Connection], None] | None = None


_V1_TASKS = """
CREATE TABLE IF NOT EXISTS tasks (
    id                TEXT PRIMARY KEY,
    title             TEXT NOT NULL,
    request           TEXT NOT NULL,
    status            TEXT NOT NULL,
    autonomy_mode     TEXT NOT NULL,
    risk_level        TEXT NOT NULL DEFAULT 'low',
    plan_summary      TEXT,
    result_summary    TEXT,
    error_message     TEXT,
    created_at        TEXT NOT NULL,
    started_at        TEXT,
    finished_at       TEXT,
    tokens_used       INTEGER NOT NULL DEFAULT 0,
    step_count        INTEGER NOT NULL DEFAULT 0,
    completed_steps   INTEGER NOT NULL DEFAULT 0,
    schedule_id       TEXT,
    metadata_json     TEXT NOT NULL DEFAULT '{}'
);
"""

_V1_STEPS = """
CREATE TABLE IF NOT EXISTS task_steps (
    id                TEXT PRIMARY KEY,
    task_id           TEXT NOT NULL,
    ordinal           INTEGER NOT NULL,
    description       TEXT NOT NULL,
    tool_name         TEXT,
    arguments_json    TEXT NOT NULL DEFAULT '{}',
    status            TEXT NOT NULL,
    risk_level        TEXT NOT NULL DEFAULT 'low',
    depends_on_json   TEXT NOT NULL DEFAULT '[]',
    attempt_count     INTEGER NOT NULL DEFAULT 0,
    max_attempts      INTEGER NOT NULL DEFAULT 2,
    result_json       TEXT,
    error_message     TEXT,
    verified          INTEGER NOT NULL DEFAULT 0,
    verification_note TEXT,
    started_at        TEXT,
    finished_at       TEXT,
    duration_ms       INTEGER,
    FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE
);
"""

_V1_APPROVALS = """
CREATE TABLE IF NOT EXISTS approvals (
    id              TEXT PRIMARY KEY,
    task_id         TEXT,
    step_id         TEXT,
    action_kind     TEXT NOT NULL,
    tool_name       TEXT,
    risk_level      TEXT NOT NULL,
    summary         TEXT NOT NULL,
    details_json    TEXT NOT NULL DEFAULT '{}',
    decision        TEXT NOT NULL DEFAULT 'pending',
    decided_by      TEXT,
    decided_at      TEXT,
    requested_at    TEXT NOT NULL,
    expires_at      TEXT,
    FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE
);
"""

_V1_AUDIT = """
CREATE TABLE IF NOT EXISTS audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at   TEXT NOT NULL,
    category      TEXT NOT NULL,
    action        TEXT NOT NULL,
    outcome       TEXT NOT NULL,
    task_id       TEXT,
    step_id       TEXT,
    tool_name     TEXT,
    risk_level    TEXT,
    summary       TEXT NOT NULL,
    details_json  TEXT NOT NULL DEFAULT '{}'
);
"""

_V1_MEMORY = """
CREATE TABLE IF NOT EXISTS memory_records (
    id            TEXT PRIMARY KEY,
    kind          TEXT NOT NULL,
    key           TEXT,
    content       TEXT NOT NULL,
    task_id       TEXT,
    importance    REAL NOT NULL DEFAULT 0.5,
    created_at    TEXT NOT NULL,
    last_used_at  TEXT,
    use_count     INTEGER NOT NULL DEFAULT 0,
    expires_at    TEXT,
    pinned        INTEGER NOT NULL DEFAULT 0,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);
"""

_V1_PREFERENCES = """
CREATE TABLE IF NOT EXISTS preferences (
    key         TEXT PRIMARY KEY,
    value_json  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
"""

_V1_SCHEDULES = """
CREATE TABLE IF NOT EXISTS schedules (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    request         TEXT NOT NULL,
    cron_expression TEXT,
    interval_minutes INTEGER,
    enabled         INTEGER NOT NULL DEFAULT 0,
    requires_approval INTEGER NOT NULL DEFAULT 1,
    last_run_at     TEXT,
    last_run_status TEXT,
    last_run_task_id TEXT,
    next_run_at     TEXT,
    run_count       INTEGER NOT NULL DEFAULT 0,
    failure_count   INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL,
    metadata_json   TEXT NOT NULL DEFAULT '{}'
);
"""

_V1_TOOL_INVOCATIONS = """
CREATE TABLE IF NOT EXISTS tool_invocations (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id        TEXT,
    step_id        TEXT,
    tool_name      TEXT NOT NULL,
    risk_level     TEXT NOT NULL,
    arguments_json TEXT NOT NULL DEFAULT '{}',
    outcome        TEXT NOT NULL,
    error_message  TEXT,
    duration_ms    INTEGER,
    invoked_at     TEXT NOT NULL
);
"""

_V1_SKILLS = """
CREATE TABLE IF NOT EXISTS skills (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    version        INTEGER NOT NULL DEFAULT 1,
    description    TEXT NOT NULL DEFAULT '',
    definition_json TEXT NOT NULL,
    approved       INTEGER NOT NULL DEFAULT 0,
    approved_at    TEXT,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    run_count      INTEGER NOT NULL DEFAULT 0,
    UNIQUE (name, version)
);
"""

_V1_INDEXES = (
    "CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);",
    "CREATE INDEX IF NOT EXISTS idx_tasks_created ON tasks(created_at DESC);",
    "CREATE INDEX IF NOT EXISTS idx_steps_task ON task_steps(task_id, ordinal);",
    "CREATE INDEX IF NOT EXISTS idx_steps_status ON task_steps(status);",
    "CREATE INDEX IF NOT EXISTS idx_approvals_decision ON approvals(decision);",
    "CREATE INDEX IF NOT EXISTS idx_approvals_task ON approvals(task_id);",
    "CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log(occurred_at DESC);",
    "CREATE INDEX IF NOT EXISTS idx_audit_category ON audit_log(category, action);",
    "CREATE INDEX IF NOT EXISTS idx_audit_task ON audit_log(task_id);",
    "CREATE INDEX IF NOT EXISTS idx_memory_kind ON memory_records(kind, created_at DESC);",
    "CREATE INDEX IF NOT EXISTS idx_memory_key ON memory_records(kind, key);",
    "CREATE INDEX IF NOT EXISTS idx_invocations_tool ON tool_invocations(tool_name);",
    "CREATE INDEX IF NOT EXISTS idx_invocations_time ON tool_invocations(invoked_at DESC);",
    "CREATE INDEX IF NOT EXISTS idx_schedules_next ON schedules(enabled, next_run_at);",
)

#: Ordered list of every migration ever shipped.
MIGRATIONS: tuple[Migration, ...] = (
    Migration(
        version=1,
        description="Initial schema: tasks, steps, approvals, audit, memory, "
        "preferences, schedules, tool invocations, skills",
        statements=(
            _V1_TASKS,
            _V1_STEPS,
            _V1_APPROVALS,
            _V1_AUDIT,
            _V1_MEMORY,
            _V1_PREFERENCES,
            _V1_SCHEDULES,
            _V1_TOOL_INVOCATIONS,
            _V1_SKILLS,
            *_V1_INDEXES,
        ),
    ),
    Migration(
        version=2,
        description="Track which run produced a scheduled task, for "
        "duplicate-execution protection across restarts",
        statements=(
            # A deterministic key per (schedule, scheduled time). The UNIQUE
            # index is what actually prevents a double run after a crash.
            "ALTER TABLE tasks ADD COLUMN idempotency_key TEXT;",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_tasks_idempotency "
            "ON tasks(idempotency_key) WHERE idempotency_key IS NOT NULL;",
        ),
    ),
)

#: The version a freshly-created database ends up at.
CURRENT_VERSION: int = max(m.version for m in MIGRATIONS)


def get_user_version(conn: sqlite3.Connection) -> int:
    return int(conn.execute("PRAGMA user_version;").fetchone()[0])


def _set_user_version(conn: sqlite3.Connection, version: int) -> None:
    # PRAGMA does not accept bound parameters, hence the f-string. The value is
    # an int from our own migration list, never user input.
    conn.execute(f"PRAGMA user_version = {int(version)};")


def apply_migrations(conn: sqlite3.Connection) -> int:
    """Bring *conn* up to :data:`CURRENT_VERSION`. Returns the new version."""
    current = get_user_version(conn)

    if current > CURRENT_VERSION:
        raise MigrationError(
            f"Database is at version {current}, newer than this build "
            f"({CURRENT_VERSION}).",
            user_message=(
                "This database was written by a newer version of Pluto. "
                "Please update the application."
            ),
        )

    for migration in MIGRATIONS:
        if migration.version <= current:
            continue
        log.info(
            "Applying migration %s: %s", migration.version, migration.description
        )
        try:
            with conn:  # transaction: commits on success, rolls back on error
                for statement in migration.statements:
                    conn.execute(statement)
                if migration.callable_step is not None:
                    migration.callable_step(conn)
                _set_user_version(conn, migration.version)
        except sqlite3.Error as exc:
            raise MigrationError(
                f"Migration {migration.version} failed: {exc}",
                user_message=(
                    "Pluto could not upgrade its local database. "
                    "Your data has not been changed."
                ),
                detail=str(exc),
            ) from exc
        current = migration.version

    return current

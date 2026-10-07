"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from pluto.core.config import Settings
from pluto.data.database import Database
from pluto.data.repositories import (
    ApprovalRepository,
    AuditRepository,
    MemoryRepository,
    PreferenceRepository,
    ScheduleRepository,
    TaskRepository,
    ToolInvocationRepository,
)
from pluto.security.paths import PathGuard


@pytest.fixture()
def db() -> Database:
    """A migrated in-memory database."""
    database = Database(":memory:")
    database.initialise()
    yield database
    database.close()


@pytest.fixture()
def file_db(tmp_path: Path) -> Database:
    """A migrated on-disk database, for durability tests."""
    database = Database(tmp_path / "pluto.db")
    database.initialise()
    yield database
    database.close()


@pytest.fixture()
def tasks(db: Database) -> TaskRepository:
    return TaskRepository(db)


@pytest.fixture()
def approvals(db: Database) -> ApprovalRepository:
    return ApprovalRepository(db)


@pytest.fixture()
def audit(db: Database) -> AuditRepository:
    return AuditRepository(db)


@pytest.fixture()
def invocations(db: Database) -> ToolInvocationRepository:
    return ToolInvocationRepository(db)


@pytest.fixture()
def memory(db: Database) -> MemoryRepository:
    return MemoryRepository(db)


@pytest.fixture()
def preferences(db: Database) -> PreferenceRepository:
    return PreferenceRepository(db)


@pytest.fixture()
def schedules(db: Database) -> ScheduleRepository:
    return ScheduleRepository(db)


@pytest.fixture()
def sandbox(tmp_path: Path) -> Path:
    """A workspace folder the agent is allowed to use."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    return workspace


@pytest.fixture()
def guard(sandbox: Path) -> PathGuard:
    return PathGuard(allowed_roots=[sandbox])


@pytest.fixture()
def settings(tmp_path: Path, sandbox: Path) -> Settings:
    return Settings(
        _env_file=None,
        data_dir=tmp_path / "data",
        allowed_folders=[sandbox],
        tool_timeout_seconds=5,
        task_timeout_seconds=30,
        max_steps_per_task=10,
    )

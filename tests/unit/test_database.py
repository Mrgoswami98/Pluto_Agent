"""Tests for the database layer, migrations and repositories."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from pluto.core.constants import (
    ApprovalDecision,
    AutonomyMode,
    MemoryKind,
    RiskLevel,
    TaskStatus,
)
from pluto.core.exceptions import MigrationError
from pluto.core.models import (
    ApprovalRequest,
    AuditEntry,
    MemoryRecord,
    Schedule,
    Task,
    TaskStep,
    ToolInvocation,
)
from pluto.data.database import Database
from pluto.data.repositories import (
    ApprovalRepository,
    AuditRepository,
    MemoryRepository,
    TaskRepository,
)
from pluto.data.schema import CURRENT_VERSION, apply_migrations


# --------------------------------------------------------------------------
# Migrations
# --------------------------------------------------------------------------
class TestMigrations:
    def test_fresh_database_reaches_current_version(self, db: Database):
        assert db.schema_version == CURRENT_VERSION
        assert db.is_current

    def test_expected_tables_exist(self, db: Database):
        expected = {
            "tasks", "task_steps", "approvals", "audit_log", "memory_records",
            "preferences", "schedules", "tool_invocations", "skills",
        }
        assert expected <= set(db.table_names())

    def test_migrations_are_idempotent(self, db: Database):
        before = db.schema_version
        assert apply_migrations(db.connect()) == before
        assert apply_migrations(db.connect()) == before

    def test_newer_database_is_refused(self, tmp_path: Path):
        database = Database(tmp_path / "future.db")
        conn = database.connect()
        conn.execute(f"PRAGMA user_version = {CURRENT_VERSION + 10};")
        with pytest.raises(MigrationError) as exc:
            database.initialise()
        assert "newer version" in exc.value.user_message.lower()
        database.close()

    def test_foreign_keys_are_enforced(self, db: Database):
        import sqlite3

        with pytest.raises(sqlite3.IntegrityError):
            db.connect().execute(
                "INSERT INTO task_steps (id, task_id, ordinal, description, status) "
                "VALUES ('s1', 'no-such-task', 0, 'orphan', 'pending');"
            )

    def test_cascade_delete_removes_steps(self, db: Database, tasks: TaskRepository):
        task = Task(title="t", request="r", steps=[TaskStep(description="s")])
        tasks.save(task)
        assert tasks.delete(task.id) is True
        assert db.fetch_value("SELECT COUNT(*) FROM task_steps;") == 0

    def test_idempotency_index_blocks_duplicates(self, db: Database, tasks: TaskRepository):
        import sqlite3

        tasks.save(Task(title="a", request="r", idempotency_key="sched-1@10:00"))
        with pytest.raises((sqlite3.IntegrityError, Exception)):
            tasks.save(Task(title="b", request="r", idempotency_key="sched-1@10:00"))

    def test_null_idempotency_keys_do_not_collide(self, tasks: TaskRepository):
        tasks.save(Task(title="a", request="r"))
        tasks.save(Task(title="b", request="r"))
        assert len(tasks.list_recent()) == 2


# --------------------------------------------------------------------------
# Task persistence
# --------------------------------------------------------------------------
class TestTaskRepository:
    def test_roundtrip_preserves_fields(self, tasks: TaskRepository):
        task = Task(
            title="Organise downloads",
            request="Sort my downloads folder by type",
            autonomy_mode=AutonomyMode.SUPERVISED,
            risk_level=RiskLevel.MEDIUM,
            steps=[
                TaskStep(description="List files", tool_name="file.list"),
                TaskStep(description="Move files", tool_name="file.move",
                         risk_level=RiskLevel.MEDIUM),
            ],
        )
        tasks.save(task)

        loaded = tasks.get(task.id)
        assert loaded is not None
        assert loaded.title == task.title
        assert loaded.autonomy_mode == AutonomyMode.SUPERVISED
        assert loaded.risk_level == RiskLevel.MEDIUM
        assert len(loaded.steps) == 2
        assert loaded.steps[0].tool_name == "file.list"
        assert loaded.steps[1].risk_level == RiskLevel.MEDIUM

    def test_update_is_an_upsert_not_a_duplicate(self, tasks: TaskRepository):
        task = Task(title="x", request="y")
        tasks.save(task)
        task.transition_to(TaskStatus.PLANNING)
        task.transition_to(TaskStatus.RUNNING)
        tasks.save(task)

        assert len(tasks.list_recent()) == 1
        assert tasks.get(task.id).status == TaskStatus.RUNNING

    def test_step_ordering_is_stable(self, tasks: TaskRepository):
        task = Task(
            title="t", request="r",
            steps=[TaskStep(description=f"step {i}", ordinal=i) for i in range(6)],
        )
        tasks.save(task)
        loaded = tasks.get(task.id)
        assert [s.description for s in loaded.steps] == [f"step {i}" for i in range(6)]

    def test_step_results_and_verification_persist(self, tasks: TaskRepository):
        step = TaskStep(description="write file", tool_name="file.write")
        task = Task(title="t", request="r", steps=[step])
        tasks.save(task)

        step.result = {"path": "out.txt", "bytes": 42}
        step.verified = True
        step.verification_note = "File exists and is 42 bytes"
        step.duration_ms = 17
        tasks.save_step(task.id, step)

        loaded = tasks.get(task.id).steps[0]
        assert loaded.result == {"path": "out.txt", "bytes": 42}
        assert loaded.verified is True
        assert loaded.duration_ms == 17

    def test_secrets_are_redacted_before_storage(self, tasks: TaskRepository, db: Database):
        task = Task(
            title="Call the API",
            request="use key sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ please",
            steps=[TaskStep(description="auth", arguments={"api_key": "sk-ant-secret"})],
        )
        tasks.save(task)
        raw = str(db.fetch_all("SELECT * FROM tasks;")[0]["request"])
        assert "sk-ant-api03" not in raw
        raw_args = str(db.fetch_all("SELECT * FROM task_steps;")[0]["arguments_json"])
        assert "sk-ant-secret" not in raw_args

    def test_list_by_status_filters(self, tasks: TaskRepository):
        for status in (TaskStatus.PENDING, TaskStatus.RUNNING, TaskStatus.COMPLETED):
            t = Task(title=str(status), request="r")
            t.status = status
            tasks.save(t)
        assert len(tasks.list_by_status(TaskStatus.COMPLETED)) == 1
        assert len(tasks.list_by_status(TaskStatus.PENDING, TaskStatus.RUNNING)) == 2

    def test_list_active_excludes_finished(self, tasks: TaskRepository):
        done = Task(title="done", request="r")
        done.status = TaskStatus.COMPLETED
        tasks.save(done)
        tasks.save(Task(title="pending", request="r"))
        active = tasks.list_active()
        assert len(active) == 1 and active[0].title == "pending"

    def test_count_by_status(self, tasks: TaskRepository):
        tasks.save(Task(title="a", request="r"))
        tasks.save(Task(title="b", request="r"))
        assert tasks.count_by_status()["pending"] == 2

    def test_get_missing_returns_none(self, tasks: TaskRepository):
        assert tasks.get("task_does_not_exist") is None

    def test_claim_idempotency_key(self, tasks: TaskRepository):
        assert tasks.claim_idempotency_key("k1") is True
        tasks.save(Task(title="t", request="r", idempotency_key="k1"))
        assert tasks.claim_idempotency_key("k1") is False

    def test_prune_removes_only_old_finished_tasks(self, tasks: TaskRepository):
        old = Task(title="old", request="r")
        old.status = TaskStatus.COMPLETED
        old.finished_at = datetime.now(UTC) - timedelta(days=120)
        tasks.save(old)

        recent = Task(title="recent", request="r")
        recent.status = TaskStatus.COMPLETED
        recent.finished_at = datetime.now(UTC)
        tasks.save(recent)

        tasks.save(Task(title="unfinished", request="r"))

        assert tasks.prune_older_than(90) == 1
        remaining = {t.title for t in tasks.list_recent()}
        assert remaining == {"recent", "unfinished"}


# --------------------------------------------------------------------------
# Durability
# --------------------------------------------------------------------------
class TestDurability:
    def test_data_survives_reconnect(self, tmp_path: Path):
        path = tmp_path / "persist.db"
        first = Database(path)
        first.initialise()
        TaskRepository(first).save(Task(id="task_fixed", title="t", request="r"))
        first.close()

        second = Database(path)
        second.initialise()
        assert TaskRepository(second).get("task_fixed") is not None
        second.close()

    def test_transaction_rolls_back_on_error(self, file_db: Database):
        repo = TaskRepository(file_db)
        repo.save(Task(id="task_keep", title="keep", request="r"))
        with pytest.raises(RuntimeError), file_db.transaction() as conn:
            conn.execute(
                "INSERT INTO tasks (id,title,request,status,autonomy_mode,"
                "risk_level,created_at) VALUES "
                "('task_gone','g','r','pending','assisted','low','2026-01-01');"
            )
            raise RuntimeError("simulated failure")
        assert repo.get("task_gone") is None
        assert repo.get("task_keep") is not None


# --------------------------------------------------------------------------
# Approvals
# --------------------------------------------------------------------------
class TestApprovalRepository:
    def test_pending_then_approved(self, approvals: ApprovalRepository):
        req = ApprovalRequest(action_kind="delete_file", summary="Delete report.xlsx",
                              risk_level=RiskLevel.HIGH)
        approvals.save(req)
        assert len(approvals.list_pending()) == 1

        approvals.record_decision(req.id, ApprovalDecision.APPROVED)
        assert approvals.get(req.id).is_approved is True
        assert approvals.list_pending() == []

    def test_denied_is_not_approved(self, approvals: ApprovalRepository):
        req = ApprovalRequest(action_kind="send_email", summary="Email the team")
        approvals.save(req)
        approvals.record_decision(req.id, ApprovalDecision.DENIED)
        assert approvals.get(req.id).is_approved is False

    def test_decision_cannot_be_overwritten(self, approvals: ApprovalRepository):
        req = ApprovalRequest(action_kind="purchase", summary="Buy item")
        approvals.save(req)
        approvals.record_decision(req.id, ApprovalDecision.DENIED)
        approvals.record_decision(req.id, ApprovalDecision.APPROVED)
        assert approvals.get(req.id).decision == ApprovalDecision.DENIED

    def test_expired_approval_is_not_approved(self, approvals: ApprovalRepository):
        req = ApprovalRequest(
            action_kind="submit_form",
            summary="Submit",
            expires_at=datetime.now(UTC) - timedelta(minutes=1),
        )
        req.decision = ApprovalDecision.APPROVED
        approvals.save(req)
        assert approvals.get(req.id).is_approved is False

    def test_expire_stale_marks_timed_out_requests(self, approvals: ApprovalRepository):
        approvals.save(ApprovalRequest(
            action_kind="x", summary="s",
            expires_at=datetime.now(UTC) - timedelta(hours=1),
        ))
        assert approvals.expire_stale() == 1
        assert approvals.list_pending() == []

    def test_pending_excludes_expired_even_before_sweep(self, approvals: ApprovalRepository):
        approvals.save(ApprovalRequest(
            action_kind="x", summary="s",
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
        ))
        assert approvals.list_pending() == []

    def test_cancel_pending_for_task(self, approvals: ApprovalRepository, tasks: TaskRepository):
        # The approvals.task_id FK is enforced, so the task must exist first.
        tasks.save(Task(id="task_1", title="t", request="r"))
        approvals.save(ApprovalRequest(task_id="task_1", action_kind="a", summary="s"))
        approvals.save(ApprovalRequest(task_id="task_1", action_kind="b", summary="s"))
        assert approvals.cancel_pending_for_task("task_1") == 2
        assert approvals.list_pending() == []

    def test_approval_for_unknown_task_is_refused(self, approvals: ApprovalRepository):
        """The FK stops an approval being attached to a task that does not exist."""
        from pluto.core.exceptions import StorageError

        with pytest.raises(StorageError):
            approvals.save(
                ApprovalRequest(task_id="task_ghost", action_kind="a", summary="s")
            )

    def test_decision_on_missing_request_returns_none(self, approvals: ApprovalRepository):
        assert approvals.record_decision("nope", ApprovalDecision.APPROVED) is None


# --------------------------------------------------------------------------
# Audit
# --------------------------------------------------------------------------
class TestAuditRepository:
    def test_entry_is_recorded_with_id(self, audit: AuditRepository):
        entry = audit.log("security", "permission_denied", outcome="denied",
                          summary="blocked write outside sandbox")
        assert entry.id is not None
        assert audit.count() == 1

    def test_secrets_redacted_in_audit(self, audit: AuditRepository, db: Database):
        audit.log("api", "call", summary="key sk-ant-api03-ABCDEFGHIJKLMNOPQRST used")
        raw = str(db.fetch_all("SELECT summary FROM audit_log;")[0]["summary"])
        assert "sk-ant-api03" not in raw

    def test_filtering(self, audit: AuditRepository):
        audit.log("security", "denied", outcome="denied", summary="a")
        audit.log("tool", "executed", outcome="success", summary="b")
        assert len(audit.list_recent(category="security")) == 1
        assert len(audit.list_recent(outcome="success")) == 1

    def test_ordered_newest_first(self, audit: AuditRepository):
        for i in range(5):
            audit.log("t", f"action_{i}", summary=str(i))
        actions = [e.action for e in audit.list_recent()]
        assert actions[0] == "action_4"

    def test_export_is_jsonl(self, audit: AuditRepository):
        import json
        audit.log("t", "a", summary="one")
        audit.log("t", "b", summary="two")
        lines = audit.export_jsonl().splitlines()
        assert len(lines) == 2
        assert all("category" in json.loads(ln) for ln in lines)

    def test_prune_by_retention(self, audit: AuditRepository):
        audit.record(AuditEntry(
            category="old", action="a", summary="s",
            occurred_at=datetime.now(UTC) - timedelta(days=200),
        ))
        audit.log("new", "b", summary="s")
        assert audit.prune_older_than(90) == 1
        assert audit.count() == 1


# --------------------------------------------------------------------------
# Tool invocations
# --------------------------------------------------------------------------
class TestToolInvocationRepository:
    def test_usage_summary_aggregates(self, invocations):
        for outcome in ("success", "success", "error"):
            invocations.record(ToolInvocation(
                tool_name="file.read", outcome=outcome, duration_ms=10,
            ))
        summary = invocations.usage_summary()[0]
        assert summary["tool_name"] == "file.read"
        assert summary["calls"] == 3
        assert summary["successes"] == 2

    def test_arguments_redacted(self, invocations, db: Database):
        invocations.record(ToolInvocation(
            tool_name="browser.fill", arguments={"password": "hunter2"},
        ))
        raw = str(db.fetch_all("SELECT arguments_json FROM tool_invocations;")[0][0])
        assert "hunter2" not in raw


# --------------------------------------------------------------------------
# Memory
# --------------------------------------------------------------------------
class TestMemoryRepository:
    def test_roundtrip(self, memory: MemoryRepository):
        record = MemoryRecord(kind=MemoryKind.PREFERENCE, key="tone",
                              content="User prefers Hinglish replies")
        memory.save(record)
        assert memory.get_by_key(MemoryKind.PREFERENCE, "tone").content == record.content

    def test_list_by_kind_sorts_pinned_first(self, memory: MemoryRepository):
        memory.save(MemoryRecord(kind=MemoryKind.EPISODIC, content="low", importance=0.1))
        memory.save(MemoryRecord(kind=MemoryKind.EPISODIC, content="pinned",
                                 importance=0.1, pinned=True))
        assert memory.list_by_kind(MemoryKind.EPISODIC)[0].content == "pinned"

    def test_search_matches_content(self, memory: MemoryRepository):
        memory.save(MemoryRecord(kind=MemoryKind.EPISODIC,
                                 content="Reorganised the invoices folder"))
        assert len(memory.search("invoices")) == 1
        assert memory.search("nonexistent") == []

    def test_expired_records_excluded(self, memory: MemoryRepository):
        memory.save(MemoryRecord(
            kind=MemoryKind.WORKING, content="stale",
            expires_at=datetime.now(UTC) - timedelta(hours=1),
        ))
        assert memory.list_by_kind(MemoryKind.WORKING) == []

    def test_prune_expired_keeps_pinned(self, memory: MemoryRepository):
        past = datetime.now(UTC) - timedelta(hours=1)
        memory.save(MemoryRecord(kind=MemoryKind.WORKING, content="a", expires_at=past))
        memory.save(MemoryRecord(kind=MemoryKind.WORKING, content="b",
                                 expires_at=past, pinned=True))
        assert memory.prune_expired() == 1

    def test_pinned_record_not_deleted(self, memory: MemoryRepository):
        record = MemoryRecord(kind=MemoryKind.PREFERENCE, content="keep", pinned=True)
        memory.save(record)
        assert memory.delete(record.id) is False

    def test_enforce_limit_drops_least_important(self, memory: MemoryRepository):
        for i in range(10):
            memory.save(MemoryRecord(kind=MemoryKind.EPISODIC, content=f"m{i}",
                                     importance=i / 10))
        assert memory.enforce_limit(MemoryKind.EPISODIC, 3) == 7
        kept = [m.content for m in memory.list_by_kind(MemoryKind.EPISODIC)]
        assert "m9" in kept and "m0" not in kept

    def test_delete_all_is_total(self, memory: MemoryRepository):
        memory.save(MemoryRecord(kind=MemoryKind.EPISODIC, content="x"))
        memory.save(MemoryRecord(kind=MemoryKind.PREFERENCE, content="y", pinned=True))
        assert memory.delete_all() == 2
        assert memory.export_all() == []

    def test_touch_increments_use_count(self, memory: MemoryRepository):
        record = MemoryRecord(kind=MemoryKind.PROCEDURAL, content="skill")
        memory.save(record)
        memory.touch(record.id)
        memory.touch(record.id)
        assert memory.get(record.id).use_count == 2

    def test_memory_content_redacted(self, memory: MemoryRepository, db: Database):
        memory.save(MemoryRecord(
            kind=MemoryKind.EPISODIC,
            content="user's key is sk-ant-api03-ABCDEFGHIJKLMNOPQRSTU",
        ))
        raw = str(db.fetch_all("SELECT content FROM memory_records;")[0][0])
        assert "sk-ant-api03" not in raw


# --------------------------------------------------------------------------
# Preferences & schedules
# --------------------------------------------------------------------------
class TestPreferenceRepository:
    def test_roundtrip_various_types(self, preferences):
        preferences.set("theme", "dark")
        preferences.set("limit", 42)
        preferences.set("folders", ["a", "b"])
        preferences.set("nested", {"x": 1})
        assert preferences.get("theme") == "dark"
        assert preferences.get("limit") == 42
        assert preferences.get("folders") == ["a", "b"]
        assert preferences.get("nested") == {"x": 1}

    def test_default_returned_when_absent(self, preferences):
        assert preferences.get("missing", "fallback") == "fallback"

    def test_overwrite(self, preferences):
        preferences.set("k", 1)
        preferences.set("k", 2)
        assert preferences.get("k") == 2
        assert len(preferences.all()) == 1


class TestScheduleRepository:
    def test_roundtrip(self, schedules):
        schedule = Schedule(name="Daily digest", request="Summarise my downloads",
                            interval_minutes=1440)
        schedules.save(schedule)
        assert schedules.get(schedule.id).name == "Daily digest"

    def test_requires_a_trigger(self):
        with pytest.raises(ValidationError):
            Schedule(name="broken", request="r")

    def test_due_requires_enabled(self, schedules):
        past = datetime.now(UTC) - timedelta(minutes=5)
        schedules.save(Schedule(name="off", request="r", interval_minutes=60,
                                enabled=False, next_run_at=past))
        assert schedules.list_due() == []

        schedules.save(Schedule(name="on", request="r", interval_minutes=60,
                                enabled=True, next_run_at=past))
        assert len(schedules.list_due()) == 1

    def test_future_schedule_not_due(self, schedules):
        future = datetime.now(UTC) + timedelta(hours=2)
        schedules.save(Schedule(name="later", request="r", interval_minutes=60,
                                enabled=True, next_run_at=future))
        assert schedules.list_due() == []

    def test_defaults_are_safe(self, schedules):
        schedule = Schedule(name="s", request="r", interval_minutes=60)
        assert schedule.enabled is False
        assert schedule.requires_approval is True

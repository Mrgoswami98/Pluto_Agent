"""Repositories — the only code that writes SQL for domain objects.

Every repository redacts before persisting. The audit log is append-only by
convention: nothing here exposes an update or delete for individual entries,
only bulk pruning by retention policy.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from pluto.core.constants import (
    ApprovalDecision,
    AutonomyMode,
    MemoryKind,
    RiskLevel,
    TaskStatus,
)
from pluto.core.logging_config import get_logger
from pluto.core.models import (
    ApprovalRequest,
    AuditEntry,
    MemoryRecord,
    Schedule,
    Task,
    TaskStep,
    ToolInvocation,
    utc_now,
)
from pluto.data.database import Database
from pluto.security.secrets import redact, redact_mapping

log = get_logger("data.repositories")


def _dt(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()


def _parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _json(value: Any) -> str:
    """Serialise, redacting any secrets on the way in."""
    if isinstance(value, dict):
        value = redact_mapping(value)
    return json.dumps(value, ensure_ascii=False, default=str)


def _unjson(value: Any, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


class TaskRepository:
    """Persistence for tasks and their steps."""

    def __init__(self, db: Database) -> None:
        self._db = db

    # -- write ------------------------------------------------------------
    def save(self, task: Task) -> Task:
        """Insert or update *task* and all of its steps, atomically."""
        with self._db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO tasks (
                    id, title, request, status, autonomy_mode, risk_level,
                    plan_summary, result_summary, error_message, created_at,
                    started_at, finished_at, tokens_used, step_count,
                    completed_steps, schedule_id, idempotency_key, metadata_json
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                    title=excluded.title,
                    status=excluded.status,
                    autonomy_mode=excluded.autonomy_mode,
                    risk_level=excluded.risk_level,
                    plan_summary=excluded.plan_summary,
                    result_summary=excluded.result_summary,
                    error_message=excluded.error_message,
                    started_at=excluded.started_at,
                    finished_at=excluded.finished_at,
                    tokens_used=excluded.tokens_used,
                    step_count=excluded.step_count,
                    completed_steps=excluded.completed_steps,
                    metadata_json=excluded.metadata_json
                """,
                (
                    task.id,
                    task.title[:300],
                    redact(task.request),
                    task.status.value,
                    task.autonomy_mode.value,
                    task.risk_level.value,
                    redact(task.plan_summary) if task.plan_summary else None,
                    redact(task.result_summary) if task.result_summary else None,
                    redact(task.error_message) if task.error_message else None,
                    _dt(task.created_at),
                    _dt(task.started_at),
                    _dt(task.finished_at),
                    task.tokens_used,
                    task.step_count,
                    task.completed_steps,
                    task.schedule_id,
                    task.idempotency_key,
                    _json(task.metadata),
                ),
            )
            for step in task.steps:
                self._save_step(conn, task.id, step)
        return task

    @staticmethod
    def _save_step(conn: sqlite3.Connection, task_id: str, step: TaskStep) -> None:
        conn.execute(
            """
            INSERT INTO task_steps (
                id, task_id, ordinal, description, tool_name, arguments_json,
                status, risk_level, depends_on_json, attempt_count, max_attempts,
                result_json, error_message, verified, verification_note,
                started_at, finished_at, duration_ms
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
                ordinal=excluded.ordinal,
                description=excluded.description,
                tool_name=excluded.tool_name,
                arguments_json=excluded.arguments_json,
                status=excluded.status,
                risk_level=excluded.risk_level,
                depends_on_json=excluded.depends_on_json,
                attempt_count=excluded.attempt_count,
                result_json=excluded.result_json,
                error_message=excluded.error_message,
                verified=excluded.verified,
                verification_note=excluded.verification_note,
                started_at=excluded.started_at,
                finished_at=excluded.finished_at,
                duration_ms=excluded.duration_ms
            """,
            (
                step.id,
                task_id,
                step.ordinal,
                redact(step.description),
                step.tool_name,
                _json(step.arguments),
                step.status.value,
                step.risk_level.value,
                _json(step.depends_on),
                step.attempt_count,
                step.max_attempts,
                _json(step.result) if step.result is not None else None,
                redact(step.error_message) if step.error_message else None,
                int(step.verified),
                redact(step.verification_note) if step.verification_note else None,
                _dt(step.started_at),
                _dt(step.finished_at),
                step.duration_ms,
            ),
        )

    def save_step(self, task_id: str, step: TaskStep) -> None:
        with self._db.transaction() as conn:
            self._save_step(conn, task_id, step)

    def claim_idempotency_key(self, key: str) -> bool:
        """True if *key* is unused. Guards against duplicate scheduled runs."""
        row = self._db.fetch_one(
            "SELECT 1 FROM tasks WHERE idempotency_key = ? LIMIT 1;", (key,)
        )
        return row is None

    # -- read -------------------------------------------------------------
    def get(self, task_id: str) -> Task | None:
        row = self._db.fetch_one("SELECT * FROM tasks WHERE id = ?;", (task_id,))
        if row is None:
            return None
        steps = self._db.fetch_all(
            "SELECT * FROM task_steps WHERE task_id = ? ORDER BY ordinal;", (task_id,)
        )
        return self._to_task(row, steps)

    def list_recent(self, limit: int = 50, offset: int = 0) -> list[Task]:
        rows = self._db.fetch_all(
            "SELECT * FROM tasks ORDER BY created_at DESC LIMIT ? OFFSET ?;",
            (limit, offset),
        )
        return [self._to_task(r, self._steps_for(r["id"])) for r in rows]

    def list_by_status(self, *statuses: TaskStatus, limit: int = 100) -> list[Task]:
        if not statuses:
            return []
        placeholders = ",".join("?" for _ in statuses)
        rows = self._db.fetch_all(
            f"SELECT * FROM tasks WHERE status IN ({placeholders}) "
            "ORDER BY created_at DESC LIMIT ?;",
            (*[s.value for s in statuses], limit),
        )
        return [self._to_task(r, self._steps_for(r["id"])) for r in rows]

    def list_active(self) -> list[Task]:
        return self.list_by_status(
            TaskStatus.PENDING,
            TaskStatus.PLANNING,
            TaskStatus.AWAITING_APPROVAL,
            TaskStatus.RUNNING,
            TaskStatus.VERIFYING,
        )

    def count_by_status(self) -> dict[str, int]:
        rows = self._db.fetch_all(
            "SELECT status, COUNT(*) AS n FROM tasks GROUP BY status;"
        )
        return {r["status"]: r["n"] for r in rows}

    def _steps_for(self, task_id: str) -> list[sqlite3.Row]:
        return self._db.fetch_all(
            "SELECT * FROM task_steps WHERE task_id = ? ORDER BY ordinal;", (task_id,)
        )

    # -- delete -----------------------------------------------------------
    def delete(self, task_id: str) -> bool:
        cursor = self._db.execute("DELETE FROM tasks WHERE id = ?;", (task_id,))
        return cursor.rowcount > 0

    def prune_older_than(self, days: int) -> int:
        cutoff = _dt(utc_now() - timedelta(days=days))
        cursor = self._db.execute(
            "DELETE FROM tasks WHERE finished_at IS NOT NULL AND finished_at < ?;",
            (cutoff,),
        )
        return cursor.rowcount

    # -- mapping ----------------------------------------------------------
    @staticmethod
    def _to_step(row: sqlite3.Row) -> TaskStep:
        return TaskStep(
            id=row["id"],
            task_id=row["task_id"],
            ordinal=row["ordinal"],
            description=row["description"],
            tool_name=row["tool_name"],
            arguments=_unjson(row["arguments_json"], {}),
            status=TaskStatus(row["status"]),
            risk_level=RiskLevel(row["risk_level"]),
            depends_on=_unjson(row["depends_on_json"], []),
            attempt_count=row["attempt_count"],
            max_attempts=row["max_attempts"],
            result=_unjson(row["result_json"], None),
            error_message=row["error_message"],
            verified=bool(row["verified"]),
            verification_note=row["verification_note"],
            started_at=_parse_dt(row["started_at"]),
            finished_at=_parse_dt(row["finished_at"]),
            duration_ms=row["duration_ms"],
        )

    @classmethod
    def _to_task(cls, row: sqlite3.Row, step_rows: Sequence[sqlite3.Row]) -> Task:
        return Task(
            id=row["id"],
            title=row["title"],
            request=row["request"],
            status=TaskStatus(row["status"]),
            autonomy_mode=AutonomyMode(row["autonomy_mode"]),
            risk_level=RiskLevel(row["risk_level"]),
            steps=[cls._to_step(s) for s in step_rows],
            plan_summary=row["plan_summary"],
            result_summary=row["result_summary"],
            error_message=row["error_message"],
            created_at=_parse_dt(row["created_at"]) or utc_now(),
            started_at=_parse_dt(row["started_at"]),
            finished_at=_parse_dt(row["finished_at"]),
            tokens_used=row["tokens_used"],
            schedule_id=row["schedule_id"],
            idempotency_key=row["idempotency_key"],
            metadata=_unjson(row["metadata_json"], {}),
        )


class ApprovalRepository:
    """Persistence for approval requests and decisions."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def save(self, approval: ApprovalRequest) -> ApprovalRequest:
        self._db.execute(
            """
            INSERT INTO approvals (
                id, task_id, step_id, action_kind, tool_name, risk_level,
                summary, details_json, decision, decided_by, decided_at,
                requested_at, expires_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
                decision=excluded.decision,
                decided_by=excluded.decided_by,
                decided_at=excluded.decided_at
            """,
            (
                approval.id,
                approval.task_id,
                approval.step_id,
                approval.action_kind,
                approval.tool_name,
                approval.risk_level.value,
                redact(approval.summary),
                _json(approval.details),
                approval.decision.value,
                approval.decided_by,
                _dt(approval.decided_at),
                _dt(approval.requested_at),
                _dt(approval.expires_at),
            ),
        )
        return approval

    def get(self, approval_id: str) -> ApprovalRequest | None:
        row = self._db.fetch_one("SELECT * FROM approvals WHERE id = ?;", (approval_id,))
        return self._to_model(row) if row else None

    def list_pending(self) -> list[ApprovalRequest]:
        rows = self._db.fetch_all(
            "SELECT * FROM approvals WHERE decision = 'pending' "
            "ORDER BY requested_at ASC;"
        )
        return [m for m in map(self._to_model, rows) if m.is_pending]

    def list_for_task(self, task_id: str) -> list[ApprovalRequest]:
        rows = self._db.fetch_all(
            "SELECT * FROM approvals WHERE task_id = ? ORDER BY requested_at;",
            (task_id,),
        )
        return [self._to_model(r) for r in rows]

    def record_decision(
        self, approval_id: str, decision: ApprovalDecision, *, decided_by: str = "user"
    ) -> ApprovalRequest | None:
        approval = self.get(approval_id)
        if approval is None:
            return None
        if approval.decision != ApprovalDecision.PENDING:
            log.warning(
                "Approval %s already decided as %s; ignoring",
                approval_id,
                approval.decision.value,
            )
            return approval
        approval.decision = decision
        approval.decided_by = decided_by
        approval.decided_at = utc_now()
        return self.save(approval)

    def expire_stale(self) -> int:
        """Mark timed-out requests as expired. Returns how many."""
        cursor = self._db.execute(
            "UPDATE approvals SET decision = 'expired' "
            "WHERE decision = 'pending' AND expires_at IS NOT NULL "
            "AND expires_at < ?;",
            (_dt(utc_now()),),
        )
        return cursor.rowcount

    def cancel_pending_for_task(self, task_id: str) -> int:
        cursor = self._db.execute(
            "UPDATE approvals SET decision = 'cancelled' "
            "WHERE task_id = ? AND decision = 'pending';",
            (task_id,),
        )
        return cursor.rowcount

    @staticmethod
    def _to_model(row: sqlite3.Row) -> ApprovalRequest:
        return ApprovalRequest(
            id=row["id"],
            task_id=row["task_id"],
            step_id=row["step_id"],
            action_kind=row["action_kind"],
            tool_name=row["tool_name"],
            risk_level=RiskLevel(row["risk_level"]),
            summary=row["summary"],
            details=_unjson(row["details_json"], {}),
            decision=ApprovalDecision(row["decision"]),
            decided_by=row["decided_by"],
            decided_at=_parse_dt(row["decided_at"]),
            requested_at=_parse_dt(row["requested_at"]) or utc_now(),
            expires_at=_parse_dt(row["expires_at"]),
        )


class AuditRepository:
    """Append-only audit trail."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def record(self, entry: AuditEntry) -> AuditEntry:
        cursor = self._db.execute(
            """
            INSERT INTO audit_log (
                occurred_at, category, action, outcome, task_id, step_id,
                tool_name, risk_level, summary, details_json
            ) VALUES (?,?,?,?,?,?,?,?,?,?)
            """,
            (
                _dt(entry.occurred_at),
                entry.category,
                entry.action,
                entry.outcome,
                entry.task_id,
                entry.step_id,
                entry.tool_name,
                entry.risk_level.value if entry.risk_level else None,
                redact(entry.summary),
                _json(entry.details),
            ),
        )
        entry.id = cursor.lastrowid
        return entry

    def log(
        self,
        category: str,
        action: str,
        *,
        outcome: str = "success",
        summary: str = "",
        **fields: Any,
    ) -> AuditEntry:
        """Convenience wrapper used throughout the codebase."""
        return self.record(
            AuditEntry(
                category=category,
                action=action,
                outcome=outcome,
                summary=summary,
                **fields,
            )
        )

    def list_recent(
        self,
        limit: int = 200,
        *,
        category: str | None = None,
        task_id: str | None = None,
        outcome: str | None = None,
    ) -> list[AuditEntry]:
        clauses: list[str] = []
        params: list[Any] = []
        if category:
            clauses.append("category = ?")
            params.append(category)
        if task_id:
            clauses.append("task_id = ?")
            params.append(task_id)
        if outcome:
            clauses.append("outcome = ?")
            params.append(outcome)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        rows = self._db.fetch_all(
            f"SELECT * FROM audit_log {where} ORDER BY occurred_at DESC, id DESC LIMIT ?;",
            tuple(params),
        )
        return [self._to_model(r) for r in rows]

    def count(self) -> int:
        return int(self._db.fetch_value("SELECT COUNT(*) FROM audit_log;", default=0))

    def prune_older_than(self, days: int) -> int:
        cutoff = _dt(utc_now() - timedelta(days=days))
        cursor = self._db.execute(
            "DELETE FROM audit_log WHERE occurred_at < ?;", (cutoff,)
        )
        return cursor.rowcount

    def export_jsonl(self) -> str:
        """Whole trail as JSON lines, for the user's data-export control."""
        lines = []
        for entry in self.list_recent(limit=1_000_000):
            lines.append(json.dumps(entry.model_dump(mode="json"), ensure_ascii=False))
        return "\n".join(lines)

    @staticmethod
    def _to_model(row: sqlite3.Row) -> AuditEntry:
        return AuditEntry(
            id=row["id"],
            occurred_at=_parse_dt(row["occurred_at"]) or utc_now(),
            category=row["category"],
            action=row["action"],
            outcome=row["outcome"],
            task_id=row["task_id"],
            step_id=row["step_id"],
            tool_name=row["tool_name"],
            risk_level=RiskLevel(row["risk_level"]) if row["risk_level"] else None,
            summary=row["summary"],
            details=_unjson(row["details_json"], {}),
        )


class ToolInvocationRepository:
    """Records of individual tool calls."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def record(self, invocation: ToolInvocation) -> ToolInvocation:
        cursor = self._db.execute(
            """
            INSERT INTO tool_invocations (
                task_id, step_id, tool_name, risk_level, arguments_json,
                outcome, error_message, duration_ms, invoked_at
            ) VALUES (?,?,?,?,?,?,?,?,?)
            """,
            (
                invocation.task_id,
                invocation.step_id,
                invocation.tool_name,
                invocation.risk_level.value,
                _json(invocation.arguments),
                invocation.outcome,
                redact(invocation.error_message) if invocation.error_message else None,
                invocation.duration_ms,
                _dt(invocation.invoked_at),
            ),
        )
        invocation.id = cursor.lastrowid
        return invocation

    def usage_summary(self) -> list[dict[str, Any]]:
        rows = self._db.fetch_all(
            """
            SELECT tool_name,
                   COUNT(*) AS calls,
                   SUM(CASE WHEN outcome = 'success' THEN 1 ELSE 0 END) AS successes,
                   AVG(duration_ms) AS avg_ms
            FROM tool_invocations
            GROUP BY tool_name
            ORDER BY calls DESC;
            """
        )
        return [dict(r) for r in rows]

    def prune_older_than(self, days: int) -> int:
        cutoff = _dt(utc_now() - timedelta(days=days))
        cursor = self._db.execute(
            "DELETE FROM tool_invocations WHERE invoked_at < ?;", (cutoff,)
        )
        return cursor.rowcount


class MemoryRepository:
    """Persistence for the memory stores."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def save(self, record: MemoryRecord) -> MemoryRecord:
        self._db.execute(
            """
            INSERT INTO memory_records (
                id, kind, key, content, task_id, importance, created_at,
                last_used_at, use_count, expires_at, pinned, metadata_json
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
                content=excluded.content,
                importance=excluded.importance,
                last_used_at=excluded.last_used_at,
                use_count=excluded.use_count,
                expires_at=excluded.expires_at,
                pinned=excluded.pinned,
                metadata_json=excluded.metadata_json
            """,
            (
                record.id,
                record.kind.value,
                record.key,
                redact(record.content),
                record.task_id,
                record.importance,
                _dt(record.created_at),
                _dt(record.last_used_at),
                record.use_count,
                _dt(record.expires_at),
                int(record.pinned),
                _json(record.metadata),
            ),
        )
        return record

    def get(self, record_id: str) -> MemoryRecord | None:
        row = self._db.fetch_one(
            "SELECT * FROM memory_records WHERE id = ?;", (record_id,)
        )
        return self._to_model(row) if row else None

    def get_by_key(self, kind: MemoryKind, key: str) -> MemoryRecord | None:
        row = self._db.fetch_one(
            "SELECT * FROM memory_records WHERE kind = ? AND key = ? "
            "ORDER BY created_at DESC LIMIT 1;",
            (kind.value, key),
        )
        return self._to_model(row) if row else None

    def list_by_kind(self, kind: MemoryKind, limit: int = 100) -> list[MemoryRecord]:
        rows = self._db.fetch_all(
            "SELECT * FROM memory_records WHERE kind = ? "
            "ORDER BY pinned DESC, importance DESC, created_at DESC LIMIT ?;",
            (kind.value, limit),
        )
        return [m for m in map(self._to_model, rows) if not m.is_expired]

    def search(self, query: str, limit: int = 20) -> list[MemoryRecord]:
        """Substring search. Deliberately simple — no embeddings, no network."""
        rows = self._db.fetch_all(
            "SELECT * FROM memory_records WHERE content LIKE ? OR key LIKE ? "
            "ORDER BY importance DESC, created_at DESC LIMIT ?;",
            (f"%{query}%", f"%{query}%", limit),
        )
        return [m for m in map(self._to_model, rows) if not m.is_expired]

    def touch(self, record_id: str) -> None:
        self._db.execute(
            "UPDATE memory_records SET use_count = use_count + 1, last_used_at = ? "
            "WHERE id = ?;",
            (_dt(utc_now()), record_id),
        )

    def delete(self, record_id: str) -> bool:
        cursor = self._db.execute(
            "DELETE FROM memory_records WHERE id = ? AND pinned = 0;", (record_id,)
        )
        return cursor.rowcount > 0

    def delete_kind(self, kind: MemoryKind) -> int:
        cursor = self._db.execute(
            "DELETE FROM memory_records WHERE kind = ?;", (kind.value,)
        )
        return cursor.rowcount

    def delete_all(self) -> int:
        """The user's "forget everything" control."""
        cursor = self._db.execute("DELETE FROM memory_records;")
        return cursor.rowcount

    def prune_expired(self) -> int:
        cursor = self._db.execute(
            "DELETE FROM memory_records WHERE expires_at IS NOT NULL "
            "AND expires_at < ? AND pinned = 0;",
            (_dt(utc_now()),),
        )
        return cursor.rowcount

    def enforce_limit(self, kind: MemoryKind, limit: int) -> int:
        """Drop the least important unpinned records beyond *limit*."""
        cursor = self._db.execute(
            """
            DELETE FROM memory_records
            WHERE kind = ? AND pinned = 0 AND id NOT IN (
                SELECT id FROM memory_records WHERE kind = ?
                ORDER BY pinned DESC, importance DESC, created_at DESC LIMIT ?
            );
            """,
            (kind.value, kind.value, limit),
        )
        return cursor.rowcount

    def export_all(self) -> list[dict[str, Any]]:
        rows = self._db.fetch_all("SELECT * FROM memory_records ORDER BY created_at;")
        return [self._to_model(r).model_dump(mode="json") for r in rows]

    @staticmethod
    def _to_model(row: sqlite3.Row) -> MemoryRecord:
        return MemoryRecord(
            id=row["id"],
            kind=MemoryKind(row["kind"]),
            key=row["key"],
            content=row["content"],
            task_id=row["task_id"],
            importance=row["importance"],
            created_at=_parse_dt(row["created_at"]) or utc_now(),
            last_used_at=_parse_dt(row["last_used_at"]),
            use_count=row["use_count"],
            expires_at=_parse_dt(row["expires_at"]),
            pinned=bool(row["pinned"]),
            metadata=_unjson(row["metadata_json"], {}),
        )


class PreferenceRepository:
    """Key/value settings saved from the UI."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def set(self, key: str, value: Any) -> None:
        self._db.execute(
            "INSERT INTO preferences (key, value_json, updated_at) VALUES (?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, "
            "updated_at=excluded.updated_at;",
            (key, _json(value), _dt(utc_now())),
        )

    def get(self, key: str, default: Any = None) -> Any:
        row = self._db.fetch_one(
            "SELECT value_json FROM preferences WHERE key = ?;", (key,)
        )
        return _unjson(row["value_json"], default) if row else default

    def all(self) -> dict[str, Any]:
        rows = self._db.fetch_all("SELECT key, value_json FROM preferences;")
        return {r["key"]: _unjson(r["value_json"], None) for r in rows}

    def delete(self, key: str) -> bool:
        return self._db.execute(
            "DELETE FROM preferences WHERE key = ?;", (key,)
        ).rowcount > 0


class ScheduleRepository:
    """Recurring workflow definitions."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def save(self, schedule: Schedule) -> Schedule:
        self._db.execute(
            """
            INSERT INTO schedules (
                id, name, request, cron_expression, interval_minutes, enabled,
                requires_approval, last_run_at, last_run_status, last_run_task_id,
                next_run_at, run_count, failure_count, created_at, metadata_json
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
                name=excluded.name,
                request=excluded.request,
                cron_expression=excluded.cron_expression,
                interval_minutes=excluded.interval_minutes,
                enabled=excluded.enabled,
                requires_approval=excluded.requires_approval,
                last_run_at=excluded.last_run_at,
                last_run_status=excluded.last_run_status,
                last_run_task_id=excluded.last_run_task_id,
                next_run_at=excluded.next_run_at,
                run_count=excluded.run_count,
                failure_count=excluded.failure_count,
                metadata_json=excluded.metadata_json
            """,
            (
                schedule.id,
                schedule.name,
                redact(schedule.request),
                schedule.cron_expression,
                schedule.interval_minutes,
                int(schedule.enabled),
                int(schedule.requires_approval),
                _dt(schedule.last_run_at),
                schedule.last_run_status,
                schedule.last_run_task_id,
                _dt(schedule.next_run_at),
                schedule.run_count,
                schedule.failure_count,
                _dt(schedule.created_at),
                _json(schedule.metadata),
            ),
        )
        return schedule

    def get(self, schedule_id: str) -> Schedule | None:
        row = self._db.fetch_one("SELECT * FROM schedules WHERE id = ?;", (schedule_id,))
        return self._to_model(row) if row else None

    def list_all(self) -> list[Schedule]:
        rows = self._db.fetch_all("SELECT * FROM schedules ORDER BY created_at DESC;")
        return [self._to_model(r) for r in rows]

    def list_due(self, now: datetime | None = None) -> list[Schedule]:
        moment = _dt(now or utc_now())
        rows = self._db.fetch_all(
            "SELECT * FROM schedules WHERE enabled = 1 AND next_run_at IS NOT NULL "
            "AND next_run_at <= ? ORDER BY next_run_at;",
            (moment,),
        )
        return [self._to_model(r) for r in rows]

    def set_enabled(self, schedule_id: str, enabled: bool) -> bool:
        return self._db.execute(
            "UPDATE schedules SET enabled = ? WHERE id = ?;",
            (int(enabled), schedule_id),
        ).rowcount > 0

    def delete(self, schedule_id: str) -> bool:
        return self._db.execute(
            "DELETE FROM schedules WHERE id = ?;", (schedule_id,)
        ).rowcount > 0

    @staticmethod
    def _to_model(row: sqlite3.Row) -> Schedule:
        return Schedule(
            id=row["id"],
            name=row["name"],
            request=row["request"],
            cron_expression=row["cron_expression"],
            interval_minutes=row["interval_minutes"],
            enabled=bool(row["enabled"]),
            requires_approval=bool(row["requires_approval"]),
            last_run_at=_parse_dt(row["last_run_at"]),
            last_run_status=row["last_run_status"],
            last_run_task_id=row["last_run_task_id"],
            next_run_at=_parse_dt(row["next_run_at"]),
            run_count=row["run_count"],
            failure_count=row["failure_count"],
            created_at=_parse_dt(row["created_at"]) or utc_now(),
            metadata=_unjson(row["metadata_json"], {}),
        )

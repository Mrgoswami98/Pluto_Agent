"""Domain models.

Pydantic models used across the whole application: the planner emits them, the
orchestrator executes them, the repositories persist them and the UI renders
them. Validation happens at the boundary so an invalid plan from the model
cannot reach the executor.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from pluto.core.constants import (
    ALLOWED_TRANSITIONS,
    STEP_TRANSITIONS,
    ApprovalDecision,
    AutonomyMode,
    MemoryKind,
    RiskLevel,
    TaskStatus,
)


def new_id(prefix: str = "") -> str:
    raw = uuid.uuid4().hex[:16]
    return f"{prefix}_{raw}" if prefix else raw


def utc_now() -> datetime:
    return datetime.now(UTC)


class PlutoModel(BaseModel):
    """Base model with shared configuration."""

    model_config = ConfigDict(
        validate_assignment=True,
        use_enum_values=False,
        extra="forbid",
        str_strip_whitespace=True,
    )


# --------------------------------------------------------------------------
# Steps and tasks
# --------------------------------------------------------------------------
class TaskStep(PlutoModel):
    """One validated unit of work."""

    id: str = Field(default_factory=lambda: new_id("step"))
    task_id: str = ""
    ordinal: int = Field(default=0, ge=0)
    description: str = Field(min_length=1, max_length=2_000)
    tool_name: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    status: TaskStatus = TaskStatus.PENDING
    risk_level: RiskLevel = RiskLevel.LOW
    depends_on: list[str] = Field(default_factory=list)
    attempt_count: int = Field(default=0, ge=0)
    max_attempts: int = Field(
        default=2,
        ge=0,
        le=5,
        description=(
            "Total attempts allowed, not extra retries. 2 means one initial "
            "try and one retry. 0 means the step is never retried, which is "
            "what high-risk steps get."
        ),
    )
    result: dict[str, Any] | None = None
    error_message: str | None = None
    verified: bool = False
    verification_note: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_ms: int | None = None

    @field_validator("depends_on")
    @classmethod
    def _no_self_dependency(cls, value: list[str], info: Any) -> list[str]:
        own = (info.data or {}).get("id")
        if own and own in value:
            raise ValueError("a step cannot depend on itself")
        return value

    @property
    def is_terminal(self) -> bool:
        return self.status.is_terminal

    @property
    def can_retry(self) -> bool:
        """Dangerous work is never retried automatically (spec §4C)."""
        if self.risk_level.rank >= RiskLevel.HIGH.rank:
            return False
        return self.attempt_count < self.max_attempts

    def transition_to(self, status: TaskStatus) -> None:
        """Move to *status*, refusing illegal transitions.

        Steps use :data:`STEP_TRANSITIONS`, not the task map: a step has no
        planning phase, and a bounded retry legitimately moves it from FAILED
        back to PENDING.
        """
        if status == self.status:
            return
        allowed = STEP_TRANSITIONS.get(self.status, frozenset())
        if status not in allowed:
            raise ValueError(
                f"Illegal step transition {self.status.value} -> {status.value}"
            )
        self.status = status


class Task(PlutoModel):
    """A user request, its plan and its outcome."""

    id: str = Field(default_factory=lambda: new_id("task"))
    title: str = Field(min_length=1, max_length=300)
    request: str = Field(min_length=1, max_length=20_000)
    status: TaskStatus = TaskStatus.PENDING
    autonomy_mode: AutonomyMode = AutonomyMode.ASSISTED
    risk_level: RiskLevel = RiskLevel.LOW
    steps: list[TaskStep] = Field(default_factory=list)
    plan_summary: str | None = None
    result_summary: str | None = None
    error_message: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    tokens_used: int = Field(default=0, ge=0)
    schedule_id: str | None = None
    idempotency_key: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _link_steps(self) -> Task:
        for index, step in enumerate(self.steps):
            if not step.task_id:
                step.task_id = self.id
            if step.ordinal == 0:
                step.ordinal = index
        return self

    @property
    def completed_steps(self) -> int:
        return sum(1 for s in self.steps if s.status == TaskStatus.COMPLETED)

    @property
    def failed_steps(self) -> int:
        return sum(1 for s in self.steps if s.status == TaskStatus.FAILED)

    @property
    def step_count(self) -> int:
        return len(self.steps)

    @property
    def progress(self) -> float:
        return self.completed_steps / self.step_count if self.step_count else 0.0

    @property
    def duration_seconds(self) -> float | None:
        if self.started_at is None:
            return None
        end = self.finished_at or utc_now()
        return (end - self.started_at).total_seconds()

    @property
    def max_step_risk(self) -> RiskLevel:
        if not self.steps:
            return RiskLevel.READ_ONLY
        return max((s.risk_level for s in self.steps), key=lambda r: r.rank)

    def transition_to(self, status: TaskStatus) -> None:
        if status == self.status:
            return
        allowed = ALLOWED_TRANSITIONS.get(self.status, frozenset())
        if status not in allowed:
            raise ValueError(
                f"Illegal task transition {self.status.value} -> {status.value}"
            )
        self.status = status
        if status == TaskStatus.RUNNING and self.started_at is None:
            self.started_at = utc_now()
        if status.is_terminal and self.finished_at is None:
            self.finished_at = utc_now()

    def step_by_id(self, step_id: str) -> TaskStep | None:
        return next((s for s in self.steps if s.id == step_id), None)

    def ready_steps(self) -> list[TaskStep]:
        """Pending steps whose dependencies have all completed."""
        done = {s.id for s in self.steps if s.status == TaskStatus.COMPLETED}
        return [
            s
            for s in self.steps
            if s.status == TaskStatus.PENDING and set(s.depends_on) <= done
        ]

    def validate_dependency_graph(self) -> None:
        """Raise if the plan has unknown or cyclic dependencies."""
        ids = {s.id for s in self.steps}
        for step in self.steps:
            unknown = set(step.depends_on) - ids
            if unknown:
                raise ValueError(
                    f"Step {step.id} depends on unknown step(s): {sorted(unknown)}"
                )

        # Depth-first cycle detection.
        WHITE, GREY, BLACK = 0, 1, 2
        colour = dict.fromkeys(ids, WHITE)
        edges = {s.id: list(s.depends_on) for s in self.steps}

        def visit(node: str, trail: list[str]) -> None:
            colour[node] = GREY
            for dep in edges.get(node, ()):
                if colour[dep] == GREY:
                    cycle = " -> ".join([*trail, node, dep])
                    raise ValueError(f"Circular dependency: {cycle}")
                if colour[dep] == WHITE:
                    visit(dep, [*trail, node])
            colour[node] = BLACK

        for node in ids:
            if colour[node] == WHITE:
                visit(node, [])


# --------------------------------------------------------------------------
# Approvals
# --------------------------------------------------------------------------
class ApprovalRequest(PlutoModel):
    """A request for a human decision."""

    id: str = Field(default_factory=lambda: new_id("appr"))
    task_id: str | None = None
    step_id: str | None = None
    action_kind: str = Field(min_length=1, max_length=100)
    tool_name: str | None = None
    risk_level: RiskLevel = RiskLevel.MEDIUM
    summary: str = Field(min_length=1, max_length=2_000)
    details: dict[str, Any] = Field(default_factory=dict)
    decision: ApprovalDecision = ApprovalDecision.PENDING
    decided_by: str | None = None
    decided_at: datetime | None = None
    requested_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime | None = None

    @property
    def is_pending(self) -> bool:
        return self.decision == ApprovalDecision.PENDING and not self.is_expired

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        return utc_now() > expires

    @property
    def is_approved(self) -> bool:
        """Expiry revokes approval — a stale yes is not a yes."""
        return self.decision == ApprovalDecision.APPROVED and not self.is_expired


# --------------------------------------------------------------------------
# Audit
# --------------------------------------------------------------------------
class AuditEntry(PlutoModel):
    """One immutable record of something that happened."""

    id: int | None = None
    occurred_at: datetime = Field(default_factory=utc_now)
    category: str = Field(min_length=1, max_length=60)
    action: str = Field(min_length=1, max_length=120)
    outcome: str = Field(default="success", max_length=40)
    task_id: str | None = None
    step_id: str | None = None
    tool_name: str | None = None
    risk_level: RiskLevel | None = None
    summary: str = Field(default="", max_length=2_000)
    details: dict[str, Any] = Field(default_factory=dict)


class ToolInvocation(PlutoModel):
    """Summary of one tool call, for the activity view."""

    id: int | None = None
    task_id: str | None = None
    step_id: str | None = None
    tool_name: str
    risk_level: RiskLevel = RiskLevel.LOW
    arguments: dict[str, Any] = Field(default_factory=dict)
    outcome: str = "success"
    error_message: str | None = None
    duration_ms: int | None = None
    invoked_at: datetime = Field(default_factory=utc_now)


# --------------------------------------------------------------------------
# Memory
# --------------------------------------------------------------------------
class MemoryRecord(PlutoModel):
    """Something Pluto remembers between tasks."""

    id: str = Field(default_factory=lambda: new_id("mem"))
    kind: MemoryKind = MemoryKind.EPISODIC
    key: str | None = Field(default=None, max_length=200)
    content: str = Field(min_length=1, max_length=20_000)
    task_id: str | None = None
    importance: float = Field(default=0.5, ge=0.0, le=1.0)
    created_at: datetime = Field(default_factory=utc_now)
    last_used_at: datetime | None = None
    use_count: int = Field(default=0, ge=0)
    expires_at: datetime | None = None
    pinned: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        return utc_now() > expires


# --------------------------------------------------------------------------
# Scheduling
# --------------------------------------------------------------------------
class Schedule(PlutoModel):
    """A recurring request."""

    id: str = Field(default_factory=lambda: new_id("sched"))
    name: str = Field(min_length=1, max_length=200)
    request: str = Field(min_length=1, max_length=10_000)
    cron_expression: str | None = None
    interval_minutes: int | None = Field(default=None, ge=1)
    enabled: bool = False
    requires_approval: bool = True
    last_run_at: datetime | None = None
    last_run_status: str | None = None
    last_run_task_id: str | None = None
    next_run_at: datetime | None = None
    run_count: int = Field(default=0, ge=0)
    failure_count: int = Field(default=0, ge=0)
    created_at: datetime = Field(default_factory=utc_now)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _needs_a_trigger(self) -> Schedule:
        if self.cron_expression is None and self.interval_minutes is None:
            raise ValueError("a schedule needs either a cron expression or an interval")
        return self


# --------------------------------------------------------------------------
# Tool results
# --------------------------------------------------------------------------
class ToolResult(PlutoModel):
    """What a tool hands back.

    ``verified`` is separate from ``success``: a tool can report that it ran
    without being able to prove the intended change actually happened. The
    orchestrator refuses to mark a step complete on ``success`` alone.
    """

    success: bool
    output: Any = None
    summary: str = Field(default="", max_length=4_000)
    verified: bool = False
    verification_note: str | None = None
    error: str | None = None
    duration_ms: int | None = None
    evidence_path: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def ok(
        cls,
        output: Any = None,
        summary: str = "",
        *,
        verified: bool = False,
        verification_note: str | None = None,
        **metadata: Any,
    ) -> ToolResult:
        return cls(
            success=True,
            output=output,
            summary=summary,
            verified=verified,
            verification_note=verification_note,
            metadata=metadata,
        )

    @classmethod
    def fail(cls, error: str, summary: str = "", **metadata: Any) -> ToolResult:
        return cls(
            success=False,
            error=error,
            summary=summary or error,
            verified=False,
            metadata=metadata,
        )

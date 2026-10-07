"""Task orchestration.

Runs a validated plan: resolves dependencies, enforces budgets, pauses for
approvals, retries what is safe to retry, verifies results, and refuses to
report success it cannot evidence.

The central rule, from spec §4C and §4G: **a step is only COMPLETED if its
result is both successful and verified.** A successful-but-unverified step
leaves the task PARTIAL, and the summary says so.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from pluto.core.constants import RiskLevel, TaskStatus
from pluto.core.exceptions import (
    ApprovalRequiredError,
    BudgetExceededError,
    EmergencyStopError,
    PermissionDeniedError,
    PlutoError,
    TaskCancelledError,
    ToolTimeoutError,
)
from pluto.core.logging_config import get_logger, task_context
from pluto.core.models import ApprovalRequest, Task, TaskStep, ToolResult, utc_now
from pluto.security.permissions import PermissionEngine
from pluto.tools.registry import ToolContext, ToolRegistry

log = get_logger("agent.orchestrator")


@dataclass
class ExecutionEvents:
    """Callbacks the UI subscribes to. All optional."""

    on_task_status: Callable[[Task], None] | None = None
    on_step_started: Callable[[Task, TaskStep], None] | None = None
    on_step_finished: Callable[[Task, TaskStep, ToolResult | None], None] | None = None
    on_approval_needed: Callable[[Task, TaskStep, ApprovalRequest], None] | None = None
    on_message: Callable[[str], None] | None = None

    def emit(self, name: str, *args: Any) -> None:
        handler = getattr(self, name, None)
        if handler is None:
            return
        try:
            handler(*args)
        except Exception as exc:  # a broken UI callback must not kill a task
            log.warning("Event handler %s raised: %s", name, exc)


@dataclass
class ExecutionReport:
    """Honest account of what happened."""

    task: Task
    completed: list[TaskStep] = field(default_factory=list)
    failed: list[TaskStep] = field(default_factory=list)
    skipped: list[TaskStep] = field(default_factory=list)
    unverified: list[TaskStep] = field(default_factory=list)
    awaiting_approval: list[TaskStep] = field(default_factory=list)
    duration_seconds: float = 0.0
    cancelled: bool = False

    @property
    def fully_successful(self) -> bool:
        return (
            not self.failed
            and not self.skipped
            and not self.unverified
            and not self.awaiting_approval
            and not self.cancelled
        )

    def summary_line(self) -> str:
        parts = [f"{len(self.completed)} step(s) completed and verified"]
        if self.unverified:
            parts.append(f"{len(self.unverified)} ran but could not be verified")
        if self.failed:
            parts.append(f"{len(self.failed)} failed")
        if self.awaiting_approval:
            parts.append(f"{len(self.awaiting_approval)} waiting for your approval")
        if self.skipped:
            parts.append(f"{len(self.skipped)} skipped")
        if self.cancelled:
            parts.append("task was cancelled")
        return "; ".join(parts) + "."


class TaskOrchestrator:
    """Executes a plan, step by step, under the permission engine."""

    def __init__(
        self,
        registry: ToolRegistry,
        permissions: PermissionEngine,
        *,
        task_repo: Any = None,
        audit_repo: Any = None,
        events: ExecutionEvents | None = None,
        max_steps: int = 25,
        task_timeout_seconds: int = 900,
    ) -> None:
        self._registry = registry
        self._permissions = permissions
        self._tasks = task_repo
        self._audit = audit_repo
        self.events = events or ExecutionEvents()
        self._max_steps = max_steps
        self._task_timeout = task_timeout_seconds
        self._cancel_events: dict[str, threading.Event] = {}
        self._lock = threading.RLock()

    # -- cancellation -----------------------------------------------------
    def cancel(self, task_id: str) -> bool:
        """Ask a running task to stop. Returns True if it was running."""
        with self._lock:
            event = self._cancel_events.get(task_id)
        if event is None:
            return False
        event.set()
        log.info("Cancellation requested for %s", task_id)
        return True

    def cancel_all(self, *, reason: str = "Emergency Stop") -> int:
        """Signal every running task. Used by the Emergency Stop button."""
        with self._lock:
            events = list(self._cancel_events.items())
        for _, event in events:
            event.set()
        if events:
            log.warning("%s: signalled %s running task(s)", reason, len(events))
        return len(events)

    def _cancel_event_for(self, task_id: str) -> threading.Event:
        with self._lock:
            event = self._cancel_events.get(task_id)
            if event is None:
                event = threading.Event()
                self._cancel_events[task_id] = event
            return event

    def _release(self, task_id: str) -> None:
        with self._lock:
            self._cancel_events.pop(task_id, None)

    # -- execution --------------------------------------------------------
    def execute(self, task: Task, *, approvals: dict[str, str] | None = None) -> ExecutionReport:
        """Run *task* to completion, or to the first thing that stops it.

        Parameters
        ----------
        approvals:
            Mapping of step id -> approval id for steps the user has already
            approved. Steps without one will pause rather than proceed.
        """
        approvals = approvals or {}
        report = ExecutionReport(task=task)
        cancel_event = self._cancel_event_for(task.id)
        started = time.perf_counter()

        with task_context(task.id):
            try:
                self._run(task, report, approvals, cancel_event, started)
            except TaskCancelledError as exc:
                report.cancelled = True
                self._finish(task, TaskStatus.CANCELLED, str(exc.user_message))
            except EmergencyStopError as exc:
                report.cancelled = True
                self._finish(task, TaskStatus.CANCELLED, str(exc.user_message))
            except BudgetExceededError as exc:
                self._finish(task, TaskStatus.PARTIAL, str(exc.user_message))
            except PlutoError as exc:
                self._finish(task, TaskStatus.FAILED, str(exc.user_message))
            finally:
                report.duration_seconds = time.perf_counter() - started
                self._release(task.id)
                self._persist(task)

        return report

    def _run(
        self,
        task: Task,
        report: ExecutionReport,
        approvals: dict[str, str],
        cancel_event: threading.Event,
        started: float,
    ) -> None:
        if task.status == TaskStatus.PENDING:
            task.transition_to(TaskStatus.PLANNING)
        if task.status in (TaskStatus.PLANNING, TaskStatus.AWAITING_APPROVAL):
            task.transition_to(TaskStatus.RUNNING)
        self.events.emit("on_task_status", task)
        self._persist(task)

        if len(task.steps) > self._max_steps:
            raise BudgetExceededError(
                f"Task has {len(task.steps)} steps; limit is {self._max_steps}",
                user_message=(
                    f"This task needs more than the {self._max_steps}-step limit."
                ),
            )

        executed = 0
        while True:
            self._check_stop(cancel_event, started)

            ready = task.ready_steps()
            if not ready:
                break

            for step in ready:
                self._check_stop(cancel_event, started)
                executed += 1
                if executed > self._max_steps:
                    raise BudgetExceededError(
                        "Step budget exhausted",
                        user_message=(
                            f"Pluto hit the {self._max_steps}-step limit for one task."
                        ),
                    )
                self._execute_step(task, step, report, approvals, cancel_event)
                self._persist(task)

                # A hard failure stops dependent work; independent steps are
                # still attempted, which is why we re-enter the loop rather
                # than breaking out entirely.
                if step.status == TaskStatus.AWAITING_APPROVAL:
                    # Nothing more can run until a human decides.
                    self._mark_blocked_dependents(task, report)
                    self._settle(task, report)
                    return

        self._mark_blocked_dependents(task, report)
        self._settle(task, report)

    def _execute_step(
        self,
        task: Task,
        step: TaskStep,
        report: ExecutionReport,
        approvals: dict[str, str],
        cancel_event: threading.Event,
    ) -> None:
        with task_context(task.id, step.id):
            step.transition_to(TaskStatus.RUNNING)
            step.started_at = utc_now()
            step.attempt_count += 1
            self.events.emit("on_step_started", task, step)

            # A reasoning step has no tool; it is complete by definition.
            if step.tool_name is None:
                step.transition_to(TaskStatus.VERIFYING)
                step.verified = True
                step.verification_note = "Reasoning step; no system change to verify."
                step.finished_at = utc_now()
                step.transition_to(TaskStatus.COMPLETED)
                report.completed.append(step)
                self.events.emit("on_step_finished", task, step, None)
                return

            context = ToolContext(
                task_id=task.id,
                step_id=step.id,
                approval_id=approvals.get(step.id),
                cancel_event=cancel_event,
            )

            try:
                result = self._registry.execute(
                    step.tool_name, step.arguments, context=context
                )
            except ApprovalRequiredError as exc:
                request = self._permissions.request_approval(
                    action_kind=self._registry.get(step.tool_name).action_kind,
                    risk_level=step.risk_level,
                    summary=step.description,
                    tool_name=step.tool_name,
                    task_id=task.id,
                    step_id=step.id,
                    details={"arguments": step.arguments},
                )
                step.transition_to(TaskStatus.AWAITING_APPROVAL)
                step.error_message = exc.user_message
                report.awaiting_approval.append(step)
                self.events.emit("on_approval_needed", task, step, request)
                return
            except (TaskCancelledError, EmergencyStopError):
                step.transition_to(TaskStatus.CANCELLED)
                step.finished_at = utc_now()
                raise
            except PermissionDeniedError as exc:
                self._fail_step(task, step, report, exc.user_message, retryable=False)
                return
            except ToolTimeoutError as exc:
                self._fail_step(task, step, report, exc.user_message, retryable=True)
                self._maybe_retry(task, step, report, approvals, cancel_event)
                return
            except PlutoError as exc:
                self._fail_step(task, step, report, exc.user_message, retryable=True)
                self._maybe_retry(task, step, report, approvals, cancel_event)
                return

            step.finished_at = utc_now()
            step.duration_ms = result.duration_ms
            step.result = {
                "summary": result.summary,
                "output": _truncate(result.output),
                "verified": result.verified,
            }

            if not result.success:
                self._fail_step(task, step, report, result.error or "Tool reported failure",
                                retryable=True)
                self._maybe_retry(task, step, report, approvals, cancel_event)
                return

            # Verification gate. Success alone is not enough.
            step.transition_to(TaskStatus.VERIFYING)
            step.verified = result.verified
            step.verification_note = result.verification_note

            if result.verified:
                step.transition_to(TaskStatus.COMPLETED)
                report.completed.append(step)
            else:
                # Ran, but we cannot prove the effect. Honest outcome: partial.
                step.transition_to(TaskStatus.PARTIAL)
                report.unverified.append(step)
                log.warning(
                    "Step %s ran but was not verified: %s",
                    step.id,
                    result.verification_note,
                )

            self.events.emit("on_step_finished", task, step, result)

    def _maybe_retry(
        self,
        task: Task,
        step: TaskStep,
        report: ExecutionReport,
        approvals: dict[str, str],
        cancel_event: threading.Event,
    ) -> None:
        """Retry a failed step if it is safe and allowed to retry."""
        if not step.can_retry:
            if step.risk_level.rank >= RiskLevel.HIGH.rank:
                log.info(
                    "Not retrying high-risk step %s — dangerous actions are never "
                    "retried automatically",
                    step.id,
                )
            return

        if cancel_event.is_set():
            return

        log.info(
            "Retrying step %s (attempt %s of %s)",
            step.id, step.attempt_count + 1, step.max_attempts + 1,
        )
        # FAILED -> PENDING is an explicit, legal transition so the main loop
        # picks the step up again on the next pass.
        step.transition_to(TaskStatus.PENDING)
        step.error_message = None
        if step in report.failed:
            report.failed.remove(step)

    def _fail_step(
        self,
        task: Task,
        step: TaskStep,
        report: ExecutionReport,
        message: str,
        *,
        retryable: bool,
    ) -> None:
        step.transition_to(TaskStatus.FAILED)
        step.error_message = message
        step.finished_at = utc_now()
        if step not in report.failed:
            report.failed.append(step)
        log.warning("Step %s failed: %s", step.id, message)
        self.events.emit("on_step_finished", task, step, None)

    def _mark_blocked_dependents(self, task: Task, report: ExecutionReport) -> None:
        """Steps whose dependencies never completed cannot run."""
        resolved = {
            s.id for s in task.steps
            if s.status in (TaskStatus.COMPLETED, TaskStatus.PARTIAL)
        }
        for step in task.steps:
            if step.status != TaskStatus.PENDING:
                continue
            if not set(step.depends_on) <= resolved:
                step.transition_to(TaskStatus.BLOCKED)
                step.error_message = "A step it depends on did not complete."
                if step not in report.skipped:
                    report.skipped.append(step)

    def _settle(self, task: Task, report: ExecutionReport) -> None:
        """Decide the task's final status from what actually happened."""
        if report.awaiting_approval:
            if task.status != TaskStatus.AWAITING_APPROVAL:
                task.transition_to(TaskStatus.AWAITING_APPROVAL)
            self.events.emit("on_task_status", task)
            return

        task.transition_to(TaskStatus.VERIFYING)

        if report.fully_successful and report.completed:
            self._finish(task, TaskStatus.COMPLETED, report.summary_line())
        elif report.completed or report.unverified:
            self._finish(task, TaskStatus.PARTIAL, report.summary_line())
        else:
            self._finish(task, TaskStatus.FAILED, report.summary_line())

    def _finish(self, task: Task, status: TaskStatus, message: str) -> None:
        if task.status.is_terminal:
            return
        if status not in (TaskStatus.COMPLETED, TaskStatus.PARTIAL, TaskStatus.FAILED,
                          TaskStatus.CANCELLED):
            status = TaskStatus.FAILED

        # Route through VERIFYING when the state machine requires it.
        try:
            task.transition_to(status)
        except ValueError:
            if task.status == TaskStatus.RUNNING and status in (
                TaskStatus.COMPLETED, TaskStatus.PARTIAL
            ):
                task.transition_to(TaskStatus.VERIFYING)
                task.transition_to(status)
            else:  # pragma: no cover - defensive
                log.error(
                    "Could not move task %s from %s to %s",
                    task.id, task.status.value, status.value,
                )
                return

        task.result_summary = message
        if status in (TaskStatus.FAILED, TaskStatus.CANCELLED):
            task.error_message = message

        log.info("Task %s finished as %s: %s", task.id, status.value, message)
        self.events.emit("on_task_status", task)
        if self._audit is not None:
            self._audit.log(
                "task",
                "finished",
                outcome=status.value,
                summary=message,
                task_id=task.id,
            )

    # -- guards -----------------------------------------------------------
    def _check_stop(self, cancel_event: threading.Event, started: float) -> None:
        self._permissions.emergency_stop.raise_if_engaged()
        if cancel_event.is_set():
            raise TaskCancelledError(
                "Task cancelled",
                user_message="The task was cancelled.",
            )
        if time.perf_counter() - started > self._task_timeout:
            raise BudgetExceededError(
                f"Task exceeded {self._task_timeout}s",
                user_message=(
                    f"The task ran past its {self._task_timeout // 60}-minute limit "
                    f"and was stopped."
                ),
            )

    def _persist(self, task: Task) -> None:
        if self._tasks is not None:
            try:
                self._tasks.save(task)
            except Exception as exc:  # persistence must not kill a run
                log.error("Could not save task %s: %s", task.id, exc)


def _truncate(value: Any, limit: int = 4_000) -> Any:
    """Keep stored step output to a sensible size."""
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + f"\n[... {len(value) - limit:,} characters omitted ...]"
    if isinstance(value, dict):
        return {k: _truncate(v, limit // 2) for k, v in list(value.items())[:50]}
    if isinstance(value, list):
        return [_truncate(v, limit // 4) for v in value[:100]]
    return value

"""Tool registry.

A tool is a typed, validated, permission-checked capability. Every tool
declares its schema, risk level and action kind up front; the registry refuses
to execute anything that has not passed :class:`~pluto.security.permissions.PermissionEngine`.

Execution pipeline, in order:

1. Look the tool up (unknown name → refuse).
2. Validate arguments against the Pydantic schema.
3. Ask the permission engine.
4. Run with a timeout and a cancellation check.
5. Record an audit entry and a tool-invocation summary, success or failure.

Step 3 cannot be skipped: :meth:`ToolRegistry.execute` is the only public entry
point and it always calls the engine.
"""

from __future__ import annotations

import inspect
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from typing import Any, ClassVar, Generic, TypeVar

from pydantic import BaseModel, ValidationError

from pluto.core.constants import (
    DEFAULT_TOOL_TIMEOUT,
    RiskLevel,
    ToolCategory,
)
from pluto.core.exceptions import (
    ApprovalRequiredError,
    PermissionDeniedError,
    PlutoError,
    SecurityError,
    ToolExecutionError,
    ToolNotFoundError,
    ToolTimeoutError,
    ToolValidationError,
)
from pluto.core.logging_config import get_logger
from pluto.core.models import ToolInvocation, ToolResult
from pluto.security.permissions import PermissionEngine
from pluto.security.secrets import redact_mapping

log = get_logger("tools.registry")

ArgsT = TypeVar("ArgsT", bound=BaseModel)


class ToolContext(BaseModel):
    """Per-invocation context handed to a tool."""

    model_config = {"arbitrary_types_allowed": True}

    task_id: str | None = None
    step_id: str | None = None
    approval_id: str | None = None
    cancel_event: Any = None
    dry_run: bool = False

    def check_cancelled(self) -> None:
        """Raise if the task has been cancelled. Call inside long loops."""
        from pluto.core.exceptions import TaskCancelledError

        if self.cancel_event is not None and self.cancel_event.is_set():
            raise TaskCancelledError(
                "Cancelled during tool execution",
                user_message="The task was cancelled.",
            )


class Tool(ABC, Generic[ArgsT]):
    """Base class for every capability Pluto has.

    Subclasses declare their identity as class attributes and implement
    :meth:`run`. Verification belongs in :meth:`verify`, which the registry
    calls after a successful run.
    """

    name: ClassVar[str]
    description: ClassVar[str]
    category: ClassVar[ToolCategory]
    risk_level: ClassVar[RiskLevel]
    action_kind: ClassVar[str]
    args_model: ClassVar[type[BaseModel]]
    timeout_seconds: ClassVar[int] = DEFAULT_TOOL_TIMEOUT
    #: Windows-only tools are skipped with a clear message elsewhere.
    requires_windows: ClassVar[bool] = False
    #: Tools that reach the network are flagged in the permissions dashboard.
    requires_network: ClassVar[bool] = False

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if inspect.isabstract(cls):
            return
        required = (
            "name", "description", "category", "risk_level",
            "action_kind", "args_model",
        )
        missing = [attr for attr in required if not hasattr(cls, attr)]
        if missing:
            raise TypeError(
                f"Tool {cls.__name__} is missing required attribute(s): "
                f"{', '.join(missing)}"
            )

    @abstractmethod
    def run(self, args: ArgsT, context: ToolContext) -> ToolResult:
        """Do the work. Raise on failure or return a failed ToolResult."""

    def verify(self, args: ArgsT, result: ToolResult, context: ToolContext) -> ToolResult:
        """Confirm the intended effect actually happened.

        The default implementation marks read-only tools verified (observing
        something *is* the verification) and leaves everything else unverified,
        which is the honest answer when a tool has not implemented a check.
        """
        if self.risk_level == RiskLevel.READ_ONLY:
            result.verified = True
            result.verification_note = "Read-only operation; the returned data is the evidence."
        return result

    # -- schema -----------------------------------------------------------
    @classmethod
    def json_schema(cls) -> dict[str, Any]:
        """Schema in the shape the Claude API expects for tool use."""
        return {
            "name": cls.name,
            "description": cls.description,
            "input_schema": cls.args_model.model_json_schema(),
        }

    @classmethod
    def describe(cls) -> dict[str, Any]:
        """Row for the permissions dashboard."""
        return {
            "name": cls.name,
            "description": cls.description,
            "category": cls.category.value,
            "risk_level": cls.risk_level.value,
            "action_kind": cls.action_kind,
            "timeout_seconds": cls.timeout_seconds,
            "requires_windows": cls.requires_windows,
            "requires_network": cls.requires_network,
        }

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<Tool {self.name} risk={self.risk_level.value}>"


class ToolRegistry:
    """Holds the tools and is the only way to run one."""

    def __init__(
        self,
        permission_engine: PermissionEngine,
        *,
        audit_repo: Any = None,
        invocation_repo: Any = None,
        default_timeout: int = DEFAULT_TOOL_TIMEOUT,
    ) -> None:
        self._tools: dict[str, Tool[Any]] = {}
        self._permissions = permission_engine
        self._audit = audit_repo
        self._invocations = invocation_repo
        self._default_timeout = default_timeout
        self._lock = threading.RLock()
        self._executor = ThreadPoolExecutor(
            max_workers=4, thread_name_prefix="pluto-tool"
        )

    # -- registration -----------------------------------------------------
    def register(self, tool: Tool[Any]) -> Tool[Any]:
        with self._lock:
            if tool.name in self._tools:
                raise ValueError(f"A tool named '{tool.name}' is already registered")
            self._tools[tool.name] = tool
        log.debug("Registered tool %s (%s)", tool.name, tool.risk_level.value)
        return tool

    def register_all(self, tools: list[Tool[Any]]) -> None:
        for tool in tools:
            self.register(tool)

    def unregister(self, name: str) -> bool:
        with self._lock:
            return self._tools.pop(name, None) is not None

    def get(self, name: str) -> Tool[Any]:
        with self._lock:
            tool = self._tools.get(name)
        if tool is None:
            available = ", ".join(sorted(self._tools)) or "none"
            raise ToolNotFoundError(
                f"No tool named '{name}'. Available: {available}",
                user_message=f"Pluto tried to use an unknown tool ('{name}').",
            )
        return tool

    def has(self, name: str) -> bool:
        with self._lock:
            return name in self._tools

    @property
    def names(self) -> list[str]:
        with self._lock:
            return sorted(self._tools)

    def list_tools(self, *, category: ToolCategory | None = None) -> list[Tool[Any]]:
        with self._lock:
            tools = list(self._tools.values())
        if category is not None:
            tools = [t for t in tools if t.category == category]
        return sorted(tools, key=lambda t: t.name)

    def schemas(self, *, enabled_only: bool = True) -> list[dict[str, Any]]:
        """Tool schemas for the Claude API, filtered by what is enabled."""
        return [
            tool.json_schema()
            for tool in self.list_tools()
            if not enabled_only or self._permissions.is_tool_enabled(tool.name)
        ]

    def describe_all(self) -> list[dict[str, Any]]:
        return [
            {**tool.describe(), "enabled": self._permissions.is_tool_enabled(tool.name)}
            for tool in self.list_tools()
        ]

    # -- execution --------------------------------------------------------
    def execute(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        *,
        context: ToolContext | None = None,
    ) -> ToolResult:
        """Validate, authorise, run, verify and record a tool call."""
        context = context or ToolContext()
        arguments = arguments or {}
        started = time.perf_counter()

        tool = self.get(name)

        # -- 1. validate -------------------------------------------------
        try:
            args = tool.args_model.model_validate(arguments)
        except ValidationError as exc:
            message = _format_validation_error(exc)
            self._record_failure(tool, arguments, context, message, started)
            raise ToolValidationError(
                f"Invalid arguments for '{name}': {message}",
                user_message=f"Pluto called {name} with invalid arguments: {message}",
            ) from exc

        # -- 2. authorise ------------------------------------------------
        self._permissions.emergency_stop.raise_if_engaged()

        decision = self._permissions.check(
            action_kind=tool.action_kind,
            risk_level=tool.risk_level,
            tool_name=tool.name,
            summary=f"{tool.name}: {_short_args(args)}",
            task_id=context.task_id,
            step_id=context.step_id,
            existing_approval_id=context.approval_id,
            details={"arguments": redact_mapping(args.model_dump())},
        )

        if decision.denied:
            self._record_failure(tool, arguments, context, decision.reason, started)
            raise PermissionDeniedError(
                f"Denied: {decision.reason}",
                user_message=decision.reason,
            )

        if decision.needs_approval:
            self._record_failure(
                tool, arguments, context, "approval required", started,
                outcome="awaiting_approval",
            )
            raise ApprovalRequiredError(
                f"Approval required for {tool.name}: {decision.reason}",
                user_message=decision.reason,
                detail=tool.action_kind,
            )

        # -- 3. dry run --------------------------------------------------
        if context.dry_run:
            return ToolResult.ok(
                summary=f"[dry run] {tool.name} would run with {_short_args(args)}",
                verified=False,
                verification_note="Dry run — nothing was executed.",
            )

        # -- 4. run with a timeout ---------------------------------------
        timeout = tool.timeout_seconds or self._default_timeout
        context.check_cancelled()

        try:
            future = self._executor.submit(tool.run, args, context)
            result = future.result(timeout=timeout)
        except FuturesTimeout as exc:
            future.cancel()
            message = f"'{tool.name}' exceeded its {timeout}s limit"
            self._record_failure(tool, arguments, context, message, started,
                                 outcome="timeout")
            raise ToolTimeoutError(
                message,
                user_message=f"{tool.name} took longer than {timeout}s and was stopped.",
            ) from exc
        except PlutoError as exc:
            # Security refusals and other Pluto errors raised from inside a
            # tool must still reach the audit trail: a refused action is
            # exactly the kind of thing the user needs to see on the record.
            self._record_failure(
                tool, arguments, context,
                getattr(exc, "user_message", None) or str(exc),
                started,
                outcome="denied" if isinstance(exc, SecurityError) else "error",
            )
            raise
        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}"
            self._record_failure(tool, arguments, context, message, started)
            raise ToolExecutionError(
                f"'{tool.name}' failed: {message}",
                user_message=f"{tool.name} ran into an error: {exc}",
                detail=message,
            ) from exc

        if not isinstance(result, ToolResult):
            message = f"'{tool.name}' returned {type(result).__name__}, not a ToolResult"
            self._record_failure(tool, arguments, context, message, started)
            raise ToolExecutionError(
                message, user_message=f"{tool.name} returned an unexpected result."
            )

        # -- 5. verify ---------------------------------------------------
        if result.success:
            try:
                result = tool.verify(args, result, context)
            except Exception as exc:  # verification must not crash the run
                log.warning("Verification raised for %s: %s", tool.name, exc)
                result.verified = False
                result.verification_note = f"Verification failed to run: {exc}"

        duration_ms = int((time.perf_counter() - started) * 1000)
        result.duration_ms = duration_ms

        self._record_invocation(
            tool, arguments, context,
            outcome="success" if result.success else "error",
            error=result.error,
            duration_ms=duration_ms,
        )
        log.info(
            "%s finished in %sms (success=%s verified=%s)",
            tool.name, duration_ms, result.success, result.verified,
        )
        return result

    # -- bookkeeping ------------------------------------------------------
    def _record_invocation(
        self,
        tool: Tool[Any],
        arguments: dict[str, Any],
        context: ToolContext,
        *,
        outcome: str,
        error: str | None = None,
        duration_ms: int | None = None,
    ) -> None:
        if self._invocations is not None:
            self._invocations.record(
                ToolInvocation(
                    task_id=context.task_id,
                    step_id=context.step_id,
                    tool_name=tool.name,
                    risk_level=tool.risk_level,
                    arguments=arguments,
                    outcome=outcome,
                    error_message=error,
                    duration_ms=duration_ms,
                )
            )
        if self._audit is not None:
            self._audit.log(
                "tool",
                tool.name,
                outcome=outcome,
                summary=error or f"{tool.name} completed",
                task_id=context.task_id,
                step_id=context.step_id,
                tool_name=tool.name,
                risk_level=tool.risk_level,
                details={"duration_ms": duration_ms},
            )

    def _record_failure(
        self,
        tool: Tool[Any],
        arguments: dict[str, Any],
        context: ToolContext,
        message: str,
        started: float,
        *,
        outcome: str = "error",
    ) -> None:
        self._record_invocation(
            tool, arguments, context,
            outcome=outcome,
            error=message,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    def shutdown(self, *, wait: bool = False) -> None:
        self._executor.shutdown(wait=wait, cancel_futures=True)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _format_validation_error(exc: ValidationError) -> str:
    parts = []
    for error in exc.errors()[:4]:
        location = ".".join(str(p) for p in error["loc"]) or "(root)"
        parts.append(f"{location}: {error['msg']}")
    return "; ".join(parts)


def _short_args(args: BaseModel, limit: int = 160) -> str:
    """One-line, redacted rendering of arguments for logs and approvals."""
    redacted = redact_mapping(args.model_dump())
    text = ", ".join(f"{k}={v!r}" for k, v in redacted.items())
    return text if len(text) <= limit else f"{text[:limit]}…"


def tool_from_function(
    func: Callable[..., ToolResult],
    *,
    name: str,
    description: str,
    category: ToolCategory,
    risk_level: RiskLevel,
    action_kind: str,
    args_model: type[BaseModel],
    timeout_seconds: int = DEFAULT_TOOL_TIMEOUT,
) -> Tool[Any]:
    """Build a Tool from a plain function. Handy for tests and simple tools."""

    class _FunctionTool(Tool[Any]):
        pass

    _FunctionTool.name = name
    _FunctionTool.description = description
    _FunctionTool.category = category
    _FunctionTool.risk_level = risk_level
    _FunctionTool.action_kind = action_kind
    _FunctionTool.args_model = args_model
    _FunctionTool.timeout_seconds = timeout_seconds
    _FunctionTool.run = lambda self, args, context: func(args, context)  # type: ignore[assignment]
    _FunctionTool.__name__ = f"FunctionTool_{name}"
    return _FunctionTool()

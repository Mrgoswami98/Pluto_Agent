"""Shared enumerations and constants.

Kept in one place so the UI, database, planner and permission engine all agree
on the exact string values that get persisted.
"""

from __future__ import annotations

from enum import Enum


class StrEnum(str, Enum):
    """String enum that serialises to its value."""

    def __str__(self) -> str:  # pragma: no cover - trivial
        return str(self.value)


class AutonomyMode(StrEnum):
    """How much latitude the agent has before it must stop and ask."""

    OBSERVE = "observe"
    """Analyse and propose only. No state-changing action is permitted."""

    ASSISTED = "assisted"
    """Ask for approval before every meaningful action."""

    WORKFLOW = "workflow"
    """Run pre-approved workflows, pausing at defined checkpoints."""

    SUPERVISED = "supervised"
    """Run eligible low-risk multi-step work inside configured limits."""

    @property
    def rank(self) -> int:
        return {"observe": 0, "assisted": 1, "workflow": 2, "supervised": 3}[self.value]


class RiskLevel(StrEnum):
    """How much damage a tool call could do."""

    READ_ONLY = "read_only"
    """Observes without changing anything outside Pluto."""

    LOW = "low"
    """Reversible, contained change (write a new file in the workspace)."""

    MEDIUM = "medium"
    """Modifies existing user data, or reaches the network."""

    HIGH = "high"
    """Destructive, irreversible, or has an external side effect."""

    CRITICAL = "critical"
    """Money, identity, security posture, or system configuration."""

    @property
    def rank(self) -> int:
        return {
            "read_only": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }[self.value]


class TaskStatus(StrEnum):
    """Lifecycle of a task or one of its steps."""

    PENDING = "pending"
    PLANNING = "planning"
    AWAITING_APPROVAL = "awaiting_approval"
    RUNNING = "running"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"
    BLOCKED = "blocked"

    @property
    def is_terminal(self) -> bool:
        return self in {
            TaskStatus.COMPLETED,
            TaskStatus.PARTIAL,
            TaskStatus.FAILED,
            TaskStatus.CANCELLED,
            TaskStatus.BLOCKED,
        }

    @property
    def is_active(self) -> bool:
        return self in {
            TaskStatus.PLANNING,
            TaskStatus.RUNNING,
            TaskStatus.VERIFYING,
        }


#: Legal task-status transitions. Anything not listed here is rejected by the
#: orchestrator, which is what stops a cancelled task quietly becoming
#: "completed" later.
ALLOWED_TRANSITIONS: dict[TaskStatus, frozenset[TaskStatus]] = {
    TaskStatus.PENDING: frozenset(
        {TaskStatus.PLANNING, TaskStatus.CANCELLED, TaskStatus.BLOCKED}
    ),
    TaskStatus.PLANNING: frozenset(
        {
            TaskStatus.AWAITING_APPROVAL,
            TaskStatus.RUNNING,
            TaskStatus.FAILED,
            TaskStatus.CANCELLED,
            TaskStatus.BLOCKED,
        }
    ),
    TaskStatus.AWAITING_APPROVAL: frozenset(
        {TaskStatus.RUNNING, TaskStatus.CANCELLED, TaskStatus.FAILED, TaskStatus.BLOCKED}
    ),
    TaskStatus.RUNNING: frozenset(
        {
            TaskStatus.AWAITING_APPROVAL,
            TaskStatus.VERIFYING,
            TaskStatus.FAILED,
            TaskStatus.CANCELLED,
            TaskStatus.PARTIAL,
            TaskStatus.BLOCKED,
        }
    ),
    TaskStatus.VERIFYING: frozenset(
        {
            TaskStatus.COMPLETED,
            TaskStatus.PARTIAL,
            TaskStatus.FAILED,
            TaskStatus.CANCELLED,
            TaskStatus.RUNNING,
        }
    ),
    # Terminal states go nowhere.
    TaskStatus.COMPLETED: frozenset(),
    TaskStatus.PARTIAL: frozenset(),
    TaskStatus.FAILED: frozenset(),
    TaskStatus.CANCELLED: frozenset(),
    TaskStatus.BLOCKED: frozenset(),
}

#: Legal step-status transitions. A step has no planning phase — it goes
#: straight from PENDING to RUNNING — so it needs its own map rather than
#: reusing the task one. FAILED -> PENDING is legal because that is how a
#: bounded retry re-queues a step.
STEP_TRANSITIONS: dict[TaskStatus, frozenset[TaskStatus]] = {
    TaskStatus.PENDING: frozenset(
        {
            TaskStatus.RUNNING,
            TaskStatus.AWAITING_APPROVAL,
            TaskStatus.CANCELLED,
            TaskStatus.BLOCKED,
            TaskStatus.FAILED,
        }
    ),
    TaskStatus.RUNNING: frozenset(
        {
            TaskStatus.VERIFYING,
            TaskStatus.AWAITING_APPROVAL,
            TaskStatus.COMPLETED,
            TaskStatus.PARTIAL,
            TaskStatus.FAILED,
            TaskStatus.CANCELLED,
        }
    ),
    TaskStatus.AWAITING_APPROVAL: frozenset(
        {
            TaskStatus.RUNNING,
            TaskStatus.PENDING,
            TaskStatus.CANCELLED,
            TaskStatus.FAILED,
            TaskStatus.BLOCKED,
        }
    ),
    TaskStatus.VERIFYING: frozenset(
        {
            TaskStatus.COMPLETED,
            TaskStatus.PARTIAL,
            TaskStatus.FAILED,
            TaskStatus.CANCELLED,
        }
    ),
    # A bounded retry moves a failed step back to pending.
    TaskStatus.FAILED: frozenset({TaskStatus.PENDING}),
    TaskStatus.PARTIAL: frozenset({TaskStatus.PENDING}),
    TaskStatus.COMPLETED: frozenset(),
    TaskStatus.CANCELLED: frozenset(),
    TaskStatus.BLOCKED: frozenset({TaskStatus.PENDING}),
}


class ApprovalDecision(StrEnum):
    """What a human said when asked."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class ToolCategory(StrEnum):
    """Used for grouping in the permissions dashboard."""

    FILESYSTEM = "filesystem"
    SPREADSHEET = "spreadsheet"
    BROWSER = "browser"
    WINDOWS = "windows"
    REPORTING = "reporting"
    SCHEDULING = "scheduling"
    SYSTEM = "system"


class MemoryKind(StrEnum):
    """Which memory store a record belongs to."""

    WORKING = "working"
    EPISODIC = "episodic"
    PREFERENCE = "preference"
    PROCEDURAL = "procedural"


#: Action kinds that always require an explicit human confirmation, in every
#: autonomy mode including Supervised. Spec §5 — a natural-language command
#: must never silently bypass these.
ALWAYS_CONFIRM_ACTIONS: frozenset[str] = frozenset(
    {
        "send_email",
        "send_message",
        "publish_content",
        "make_payment",
        "purchase",
        "submit_form",
        "delete_file",
        "overwrite_file",
        "change_permissions",
        "install_software",
        "system_configuration",
        "share_external",
        "run_command",
    }
)

#: Filesystem locations the agent must never touch, whatever the allow-list
#: says. Matched case-insensitively against the resolved path.
FORBIDDEN_PATH_FRAGMENTS: tuple[str, ...] = (
    "windows\\system32",
    "windows\\syswow64",
    "program files\\windows defender",
    "\\$recycle.bin",
    "\\system volume information",
    "appdata\\roaming\\microsoft\\crypto",
    "appdata\\local\\microsoft\\credentials",
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/.ssh/",
    "/.aws/",
    "/.gnupg/",
    "/proc/",
    "/sys/",
    "/dev/",
)

#: File extensions the agent refuses to create or execute without a critical
#: approval, because they run code.
EXECUTABLE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".exe", ".com", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe",
        ".js", ".jse", ".wsf", ".wsh", ".msi", ".msp", ".scr", ".cpl",
        ".dll", ".sys", ".reg", ".hta", ".jar", ".app", ".sh",
    }
)

#: Default per-tool timeout, seconds.
DEFAULT_TOOL_TIMEOUT = 60

#: Default ceiling on steps in a single task.
DEFAULT_MAX_STEPS = 25

#: Default wall-clock budget for a task, seconds.
DEFAULT_TASK_TIMEOUT = 900

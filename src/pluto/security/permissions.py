"""Centralised permission enforcement.

Every tool call goes through :meth:`PermissionEngine.check`. There is no second
path — a tool that bypasses the engine is a bug, and the registry refuses to
execute a tool that was not checked.

The decision is a function of four things:

1. the current autonomy mode,
2. the tool's declared risk level,
3. whether the action kind is on the always-confirm list,
4. whether a valid, unexpired approval already exists.

Rule of precedence: **always-confirm wins over everything**. Supervised
autonomy does not grant the right to send an email or spend money, and a
natural-language instruction cannot lower a risk level (spec §5).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING

from pluto.core.constants import (
    ALWAYS_CONFIRM_ACTIONS,
    ApprovalDecision,
    AutonomyMode,
    RiskLevel,
)
from pluto.core.logging_config import get_logger
from pluto.core.models import ApprovalRequest, utc_now

if TYPE_CHECKING:
    from pluto.data.repositories import ApprovalRepository, AuditRepository

log = get_logger("security.permissions")


class Verdict(str):
    """Marker type for readability in logs."""


ALLOW = "allow"
REQUIRE_APPROVAL = "require_approval"
DENY = "deny"


@dataclass(frozen=True)
class PermissionDecision:
    """The outcome of a permission check."""

    verdict: str
    reason: str
    risk_level: RiskLevel
    action_kind: str
    tool_name: str | None = None
    requires_confirmation: bool = False
    approval_id: str | None = None
    details: dict[str, object] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.verdict == ALLOW

    @property
    def denied(self) -> bool:
        return self.verdict == DENY

    @property
    def needs_approval(self) -> bool:
        return self.verdict == REQUIRE_APPROVAL


#: Risk at or above which each mode must stop and ask. Observe never acts at
#: all beyond read-only; Supervised still stops at HIGH.
_APPROVAL_THRESHOLD: dict[AutonomyMode, int] = {
    AutonomyMode.OBSERVE: RiskLevel.LOW.rank,
    AutonomyMode.ASSISTED: RiskLevel.LOW.rank,
    AutonomyMode.WORKFLOW: RiskLevel.MEDIUM.rank,
    AutonomyMode.SUPERVISED: RiskLevel.HIGH.rank,
}


class EmergencyStop:
    """Global kill switch.

    Thread-safe. Once engaged, every permission check denies until it is
    explicitly reset, and running work is asked to cancel through
    :attr:`event`, which cooperating code polls.
    """

    def __init__(self) -> None:
        self._event = threading.Event()
        self._reason: str | None = None
        self._lock = threading.Lock()

    @property
    def engaged(self) -> bool:
        return self._event.is_set()

    @property
    def event(self) -> threading.Event:
        """Pollable by long-running operations."""
        return self._event

    @property
    def reason(self) -> str | None:
        return self._reason

    def engage(self, reason: str = "Emergency Stop pressed") -> None:
        with self._lock:
            self._reason = reason
            self._event.set()
        log.warning("EMERGENCY STOP engaged: %s", reason)

    def reset(self) -> None:
        with self._lock:
            self._event.clear()
            self._reason = None
        log.info("Emergency stop reset; Pluto may act again")

    def raise_if_engaged(self) -> None:
        from pluto.core.exceptions import EmergencyStopError

        if self.engaged:
            raise EmergencyStopError(
                f"Emergency stop engaged: {self._reason}",
                user_message=(
                    "Emergency Stop is active. Reset it before Pluto can continue."
                ),
            )


class PermissionEngine:
    """The single decision point for whether an action may proceed."""

    def __init__(
        self,
        *,
        autonomy_mode: AutonomyMode = AutonomyMode.ASSISTED,
        approval_repo: ApprovalRepository | None = None,
        audit_repo: AuditRepository | None = None,
        emergency_stop: EmergencyStop | None = None,
        approval_ttl_minutes: int = 15,
    ) -> None:
        self._mode = autonomy_mode
        self._approvals = approval_repo
        self._audit = audit_repo
        self.emergency_stop = emergency_stop or EmergencyStop()
        self._approval_ttl = timedelta(minutes=approval_ttl_minutes)
        self._enabled_tools: set[str] | None = None
        self._disabled_tools: set[str] = set()
        self._lock = threading.RLock()

    # -- configuration ----------------------------------------------------
    @property
    def autonomy_mode(self) -> AutonomyMode:
        return self._mode

    def set_autonomy_mode(self, mode: AutonomyMode) -> None:
        with self._lock:
            previous, self._mode = self._mode, mode
        log.info("Autonomy mode changed: %s -> %s", previous.value, mode.value)
        if self._audit is not None:
            self._audit.log(
                "security",
                "autonomy_mode_changed",
                summary=f"{previous.value} -> {mode.value}",
                details={"from": previous.value, "to": mode.value},
            )

    def set_tool_allowlist(self, tool_names: set[str] | None) -> None:
        """Restrict to an explicit set of tools. ``None`` means no restriction."""
        with self._lock:
            self._enabled_tools = set(tool_names) if tool_names is not None else None

    def disable_tool(self, tool_name: str) -> None:
        with self._lock:
            self._disabled_tools.add(tool_name)

    def enable_tool(self, tool_name: str) -> None:
        with self._lock:
            self._disabled_tools.discard(tool_name)

    def is_tool_enabled(self, tool_name: str) -> bool:
        with self._lock:
            if tool_name in self._disabled_tools:
                return False
            if self._enabled_tools is None:
                return True
            return tool_name in self._enabled_tools

    # -- the decision -----------------------------------------------------
    def check(
        self,
        *,
        action_kind: str,
        risk_level: RiskLevel,
        tool_name: str | None = None,
        summary: str = "",
        task_id: str | None = None,
        step_id: str | None = None,
        existing_approval_id: str | None = None,
        details: dict[str, object] | None = None,
    ) -> PermissionDecision:
        """Decide whether this action may run right now."""
        details = details or {}

        def decide(verdict: str, reason: str, **extra: object) -> PermissionDecision:
            decision = PermissionDecision(
                verdict=verdict,
                reason=reason,
                risk_level=risk_level,
                action_kind=action_kind,
                tool_name=tool_name,
                requires_confirmation=verdict == REQUIRE_APPROVAL,
                details={**details, **extra},
                approval_id=extra.get("approval_id"),  # type: ignore[arg-type]
            )
            self._record(decision, summary=summary, task_id=task_id, step_id=step_id)
            return decision

        # 1. Emergency stop beats everything.
        if self.emergency_stop.engaged:
            return decide(DENY, "Emergency Stop is engaged")

        # 2. Tool must be enabled.
        if tool_name and not self.is_tool_enabled(tool_name):
            return decide(DENY, f"Tool '{tool_name}' is disabled in Permissions")

        # 3. Observe mode never changes anything.
        if self._mode == AutonomyMode.OBSERVE and risk_level != RiskLevel.READ_ONLY:
            return decide(
                DENY,
                "Observe Mode only permits read-only actions. "
                "Switch modes to let Pluto act.",
            )

        # 4. Always-confirm actions need a human, in every mode.
        is_always_confirm = action_kind in ALWAYS_CONFIRM_ACTIONS

        # 5. An existing valid approval satisfies the requirement.
        if existing_approval_id and self._approval_is_valid(
            existing_approval_id, action_kind=action_kind, risk_level=risk_level
        ):
            return decide(
                ALLOW,
                "Covered by an explicit approval",
                approval_id=existing_approval_id,
            )

        if is_always_confirm:
            return decide(
                REQUIRE_APPROVAL,
                f"'{action_kind}' always needs your explicit confirmation",
                always_confirm=True,
            )

        # 6. Read-only work proceeds in any mode.
        if risk_level == RiskLevel.READ_ONLY:
            return decide(ALLOW, "Read-only action")

        # 7. Otherwise compare against the mode's threshold.
        threshold = _APPROVAL_THRESHOLD[self._mode]
        if risk_level.rank >= threshold:
            return decide(
                REQUIRE_APPROVAL,
                f"{risk_level.value} risk needs approval in "
                f"{self._mode.value} mode",
            )

        return decide(ALLOW, f"{risk_level.value} risk is permitted in {self._mode.value} mode")

    # -- approvals --------------------------------------------------------
    def request_approval(
        self,
        *,
        action_kind: str,
        risk_level: RiskLevel,
        summary: str,
        tool_name: str | None = None,
        task_id: str | None = None,
        step_id: str | None = None,
        details: dict[str, object] | None = None,
    ) -> ApprovalRequest:
        """Create a pending approval for the UI to surface."""
        request = ApprovalRequest(
            task_id=task_id,
            step_id=step_id,
            action_kind=action_kind,
            tool_name=tool_name,
            risk_level=risk_level,
            summary=summary,
            details=details or {},
            expires_at=utc_now() + self._approval_ttl,
        )
        if self._approvals is not None:
            self._approvals.save(request)
        log.info(
            "Approval requested: %s (%s risk) — %s",
            action_kind,
            risk_level.value,
            summary,
        )
        return request

    def _approval_is_valid(
        self, approval_id: str, *, action_kind: str, risk_level: RiskLevel
    ) -> bool:
        """An approval only covers the action it was granted for."""
        if self._approvals is None:
            return False
        approval = self._approvals.get(approval_id)
        if approval is None:
            return False
        if not approval.is_approved:
            return False
        if approval.action_kind != action_kind:
            log.warning(
                "Approval %s was for '%s', not '%s' — refusing to reuse it",
                approval_id,
                approval.action_kind,
                action_kind,
            )
            return False
        if approval.risk_level.rank < risk_level.rank:
            log.warning(
                "Approval %s covered %s risk, action is %s — refusing",
                approval_id,
                approval.risk_level.value,
                risk_level.value,
            )
            return False
        return True

    def resolve_approval(
        self, approval_id: str, approved: bool, *, decided_by: str = "user"
    ) -> ApprovalRequest | None:
        if self._approvals is None:
            return None
        decision = (
            ApprovalDecision.APPROVED if approved else ApprovalDecision.DENIED
        )
        result = self._approvals.record_decision(
            approval_id, decision, decided_by=decided_by
        )
        if self._audit is not None and result is not None:
            self._audit.log(
                "security",
                "approval_decided",
                outcome="approved" if approved else "denied",
                summary=result.summary,
                task_id=result.task_id,
                step_id=result.step_id,
                tool_name=result.tool_name,
                risk_level=result.risk_level,
                details={"approval_id": approval_id, "decided_by": decided_by},
            )
        return result

    # -- audit ------------------------------------------------------------
    def _record(
        self,
        decision: PermissionDecision,
        *,
        summary: str,
        task_id: str | None,
        step_id: str | None,
    ) -> None:
        if self._audit is None:
            return
        self._audit.log(
            "permission",
            decision.action_kind,
            outcome=decision.verdict,
            summary=summary or decision.reason,
            task_id=task_id,
            step_id=step_id,
            tool_name=decision.tool_name,
            risk_level=decision.risk_level,
            details={"reason": decision.reason, "mode": self._mode.value},
        )

    # -- introspection ----------------------------------------------------
    def describe(self) -> dict[str, object]:
        """Snapshot for the permissions dashboard."""
        with self._lock:
            return {
                "autonomy_mode": self._mode.value,
                "emergency_stop_engaged": self.emergency_stop.engaged,
                "emergency_stop_reason": self.emergency_stop.reason,
                "approval_threshold": RiskLevel(
                    next(
                        name
                        for name, rank in {
                            r.value: r.rank for r in RiskLevel
                        }.items()
                        if rank == _APPROVAL_THRESHOLD[self._mode]
                    )
                ).value,
                "always_confirm_actions": sorted(ALWAYS_CONFIRM_ACTIONS),
                "disabled_tools": sorted(self._disabled_tools),
                "tool_allowlist": (
                    sorted(self._enabled_tools)
                    if self._enabled_tools is not None
                    else None
                ),
            }

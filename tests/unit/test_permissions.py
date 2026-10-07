"""Tests for permission enforcement, the emergency stop and the tool registry.

These encode the product's safety promises. A failure here is a security
regression, not a style issue.
"""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import BaseModel, Field

from pluto.core.constants import (
    ALWAYS_CONFIRM_ACTIONS,
    ApprovalDecision,
    AutonomyMode,
    RiskLevel,
    ToolCategory,
)
from pluto.core.exceptions import (
    ApprovalRequiredError,
    EmergencyStopError,
    PermissionDeniedError,
    ToolExecutionError,
    ToolNotFoundError,
    ToolTimeoutError,
    ToolValidationError,
)
from pluto.core.models import ApprovalRequest, ToolResult
from pluto.data.repositories import (
    ApprovalRepository,
    AuditRepository,
    ToolInvocationRepository,
)
from pluto.security.permissions import (
    ALLOW,
    DENY,
    REQUIRE_APPROVAL,
    EmergencyStop,
    PermissionEngine,
)
from pluto.tools.registry import Tool, ToolContext, ToolRegistry


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------
@pytest.fixture()
def engine(approvals: ApprovalRepository, audit: AuditRepository) -> PermissionEngine:
    return PermissionEngine(
        autonomy_mode=AutonomyMode.ASSISTED,
        approval_repo=approvals,
        audit_repo=audit,
    )


class EchoArgs(BaseModel):
    text: str = Field(min_length=1, max_length=100)
    count: int = Field(default=1, ge=1, le=5)


class EchoTool(Tool[EchoArgs]):
    name = "test.echo"
    description = "Echo text back."
    category = ToolCategory.SYSTEM
    risk_level = RiskLevel.READ_ONLY
    action_kind = "read_data"
    args_model = EchoArgs

    def run(self, args: EchoArgs, context: ToolContext) -> ToolResult:
        return ToolResult.ok(output=args.text * args.count, summary="echoed")


class WriteArgs(BaseModel):
    target: str


class WriteTool(Tool[WriteArgs]):
    name = "test.write"
    description = "Pretend to write a file."
    category = ToolCategory.FILESYSTEM
    risk_level = RiskLevel.MEDIUM
    action_kind = "write_file"
    args_model = WriteArgs

    def run(self, args: WriteArgs, context: ToolContext) -> ToolResult:
        return ToolResult.ok(output=args.target, summary="written")


class DeleteTool(Tool[WriteArgs]):
    name = "test.delete"
    description = "Pretend to delete a file."
    category = ToolCategory.FILESYSTEM
    risk_level = RiskLevel.HIGH
    action_kind = "delete_file"
    args_model = WriteArgs

    def run(self, args: WriteArgs, context: ToolContext) -> ToolResult:
        return ToolResult.ok(output=args.target, summary="deleted")


class BoomTool(Tool[EchoArgs]):
    name = "test.boom"
    description = "Always raises."
    category = ToolCategory.SYSTEM
    risk_level = RiskLevel.READ_ONLY
    action_kind = "read_data"
    args_model = EchoArgs

    def run(self, args: EchoArgs, context: ToolContext) -> ToolResult:
        raise RuntimeError("deliberate failure")


class SlowTool(Tool[EchoArgs]):
    name = "test.slow"
    description = "Sleeps past its timeout."
    category = ToolCategory.SYSTEM
    risk_level = RiskLevel.READ_ONLY
    action_kind = "read_data"
    args_model = EchoArgs
    timeout_seconds = 1

    def run(self, args: EchoArgs, context: ToolContext) -> ToolResult:
        time.sleep(5)
        return ToolResult.ok(summary="never reached")


class BadReturnTool(Tool[EchoArgs]):
    name = "test.badreturn"
    description = "Returns the wrong type."
    category = ToolCategory.SYSTEM
    risk_level = RiskLevel.READ_ONLY
    action_kind = "read_data"
    args_model = EchoArgs

    def run(self, args: EchoArgs, context: ToolContext):  # type: ignore[override]
        return "not a ToolResult"


@pytest.fixture()
def registry(
    engine: PermissionEngine,
    audit: AuditRepository,
    invocations: ToolInvocationRepository,
) -> ToolRegistry:
    reg = ToolRegistry(engine, audit_repo=audit, invocation_repo=invocations)
    reg.register_all([EchoTool(), WriteTool(), DeleteTool(), BoomTool(),
                      SlowTool(), BadReturnTool()])
    yield reg
    reg.shutdown()


# --------------------------------------------------------------------------
# Autonomy modes
# --------------------------------------------------------------------------
class TestAutonomyModes:
    def test_observe_mode_permits_read_only(self, engine: PermissionEngine):
        engine.set_autonomy_mode(AutonomyMode.OBSERVE)
        decision = engine.check(action_kind="read_data", risk_level=RiskLevel.READ_ONLY)
        assert decision.verdict == ALLOW

    @pytest.mark.parametrize(
        "risk", [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
    )
    def test_observe_mode_denies_every_change(self, engine: PermissionEngine, risk):
        engine.set_autonomy_mode(AutonomyMode.OBSERVE)
        decision = engine.check(action_kind="write_file", risk_level=risk)
        assert decision.verdict == DENY

    def test_assisted_mode_asks_before_low_risk_change(self, engine: PermissionEngine):
        engine.set_autonomy_mode(AutonomyMode.ASSISTED)
        decision = engine.check(action_kind="write_file", risk_level=RiskLevel.LOW)
        assert decision.verdict == REQUIRE_APPROVAL

    def test_workflow_mode_allows_low_but_asks_at_medium(self, engine: PermissionEngine):
        engine.set_autonomy_mode(AutonomyMode.WORKFLOW)
        assert engine.check(action_kind="write_file",
                            risk_level=RiskLevel.LOW).verdict == ALLOW
        assert engine.check(action_kind="write_file",
                            risk_level=RiskLevel.MEDIUM).verdict == REQUIRE_APPROVAL

    def test_supervised_allows_medium_but_asks_at_high(self, engine: PermissionEngine):
        engine.set_autonomy_mode(AutonomyMode.SUPERVISED)
        assert engine.check(action_kind="write_file",
                            risk_level=RiskLevel.MEDIUM).verdict == ALLOW
        assert engine.check(action_kind="modify_data",
                            risk_level=RiskLevel.HIGH).verdict == REQUIRE_APPROVAL

    def test_read_only_allowed_in_every_mode(self, engine: PermissionEngine):
        for mode in AutonomyMode:
            engine.set_autonomy_mode(mode)
            assert engine.check(action_kind="read_data",
                                risk_level=RiskLevel.READ_ONLY).verdict == ALLOW


# --------------------------------------------------------------------------
# Always-confirm actions — the core promise of spec section 5
# --------------------------------------------------------------------------
class TestAlwaysConfirm:
    @pytest.mark.parametrize("action", sorted(ALWAYS_CONFIRM_ACTIONS))
    def test_never_auto_approved_in_supervised_mode(
        self, engine: PermissionEngine, action: str
    ):
        """Supervised autonomy must not grant these, even at low declared risk."""
        engine.set_autonomy_mode(AutonomyMode.SUPERVISED)
        decision = engine.check(action_kind=action, risk_level=RiskLevel.LOW)
        assert decision.verdict == REQUIRE_APPROVAL, (
            f"'{action}' was auto-approved — this is a security regression"
        )

    @pytest.mark.parametrize("action", sorted(ALWAYS_CONFIRM_ACTIONS))
    def test_never_auto_approved_in_any_mode(self, engine: PermissionEngine, action: str):
        for mode in AutonomyMode:
            engine.set_autonomy_mode(mode)
            decision = engine.check(action_kind=action, risk_level=RiskLevel.READ_ONLY)
            assert decision.verdict in (REQUIRE_APPROVAL, DENY), (
                f"'{action}' slipped through in {mode.value} mode"
            )

    def test_low_declared_risk_does_not_downgrade_always_confirm(
        self, engine: PermissionEngine
    ):
        """A plan claiming 'send_email' is read-only must still be stopped."""
        engine.set_autonomy_mode(AutonomyMode.SUPERVISED)
        decision = engine.check(action_kind="send_email", risk_level=RiskLevel.READ_ONLY)
        assert decision.verdict == REQUIRE_APPROVAL
        assert decision.details.get("always_confirm") is True


# --------------------------------------------------------------------------
# Approvals
# --------------------------------------------------------------------------
class TestApprovalFlow:
    def test_valid_approval_permits_the_action(
        self, engine: PermissionEngine, approvals: ApprovalRepository
    ):
        request = engine.request_approval(
            action_kind="delete_file", risk_level=RiskLevel.HIGH,
            summary="Delete old.csv",
        )
        engine.resolve_approval(request.id, approved=True)
        decision = engine.check(
            action_kind="delete_file", risk_level=RiskLevel.HIGH,
            existing_approval_id=request.id,
        )
        assert decision.verdict == ALLOW

    def test_denied_approval_does_not_permit(self, engine: PermissionEngine):
        request = engine.request_approval(
            action_kind="delete_file", risk_level=RiskLevel.HIGH, summary="Delete",
        )
        engine.resolve_approval(request.id, approved=False)
        decision = engine.check(
            action_kind="delete_file", risk_level=RiskLevel.HIGH,
            existing_approval_id=request.id,
        )
        assert decision.verdict == REQUIRE_APPROVAL

    def test_approval_cannot_be_reused_for_a_different_action(
        self, engine: PermissionEngine
    ):
        """Approving a file delete must not authorise sending an email."""
        request = engine.request_approval(
            action_kind="delete_file", risk_level=RiskLevel.HIGH, summary="Delete",
        )
        engine.resolve_approval(request.id, approved=True)
        decision = engine.check(
            action_kind="send_email", risk_level=RiskLevel.HIGH,
            existing_approval_id=request.id,
        )
        assert decision.verdict == REQUIRE_APPROVAL

    def test_approval_cannot_cover_higher_risk_than_granted(
        self, engine: PermissionEngine
    ):
        request = engine.request_approval(
            action_kind="write_file", risk_level=RiskLevel.LOW, summary="Write",
        )
        engine.resolve_approval(request.id, approved=True)
        decision = engine.check(
            action_kind="write_file", risk_level=RiskLevel.CRITICAL,
            existing_approval_id=request.id,
        )
        assert decision.verdict == REQUIRE_APPROVAL

    def test_expired_approval_does_not_permit(
        self, engine: PermissionEngine, approvals: ApprovalRepository
    ):
        request = ApprovalRequest(
            action_kind="delete_file", risk_level=RiskLevel.HIGH, summary="Delete",
            decision=ApprovalDecision.APPROVED,
            expires_at=datetime.now(UTC) - timedelta(minutes=1),
        )
        approvals.save(request)
        decision = engine.check(
            action_kind="delete_file", risk_level=RiskLevel.HIGH,
            existing_approval_id=request.id,
        )
        assert decision.verdict == REQUIRE_APPROVAL

    def test_unknown_approval_id_does_not_permit(self, engine: PermissionEngine):
        decision = engine.check(
            action_kind="delete_file", risk_level=RiskLevel.HIGH,
            existing_approval_id="appr_fabricated",
        )
        assert decision.verdict == REQUIRE_APPROVAL

    def test_requested_approval_has_an_expiry(self, engine: PermissionEngine):
        request = engine.request_approval(
            action_kind="purchase", risk_level=RiskLevel.CRITICAL, summary="Buy",
        )
        assert request.expires_at is not None


# --------------------------------------------------------------------------
# Emergency stop
# --------------------------------------------------------------------------
class TestEmergencyStop:
    def test_blocks_every_action_including_read_only(self, engine: PermissionEngine):
        engine.emergency_stop.engage("user pressed stop")
        for risk in RiskLevel:
            assert engine.check(action_kind="read_data", risk_level=risk).verdict == DENY

    def test_overrides_a_valid_approval(self, engine: PermissionEngine):
        request = engine.request_approval(
            action_kind="delete_file", risk_level=RiskLevel.HIGH, summary="Delete",
        )
        engine.resolve_approval(request.id, approved=True)
        engine.emergency_stop.engage()
        decision = engine.check(
            action_kind="delete_file", risk_level=RiskLevel.HIGH,
            existing_approval_id=request.id,
        )
        assert decision.verdict == DENY

    def test_reset_restores_normal_operation(self, engine: PermissionEngine):
        engine.emergency_stop.engage()
        engine.emergency_stop.reset()
        assert engine.check(action_kind="read_data",
                            risk_level=RiskLevel.READ_ONLY).verdict == ALLOW

    def test_raise_if_engaged(self):
        stop = EmergencyStop()
        stop.raise_if_engaged()  # no-op when clear
        stop.engage("halt")
        with pytest.raises(EmergencyStopError):
            stop.raise_if_engaged()

    def test_event_is_observable_by_workers(self):
        stop = EmergencyStop()
        seen = threading.Event()

        def worker() -> None:
            if stop.event.wait(timeout=2):
                seen.set()

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        stop.engage()
        thread.join(timeout=3)
        assert seen.is_set(), "running work was not signalled to cancel"

    def test_reason_is_recorded(self):
        stop = EmergencyStop()
        stop.engage("browser went to the wrong site")
        assert stop.reason == "browser went to the wrong site"


# --------------------------------------------------------------------------
# Tool enable/disable
# --------------------------------------------------------------------------
class TestToolGating:
    def test_disabled_tool_is_denied(self, engine: PermissionEngine):
        engine.disable_tool("test.write")
        decision = engine.check(action_kind="write_file", risk_level=RiskLevel.LOW,
                                tool_name="test.write")
        assert decision.verdict == DENY

    def test_re_enabling_restores_access(self, engine: PermissionEngine):
        engine.set_autonomy_mode(AutonomyMode.SUPERVISED)
        engine.disable_tool("test.write")
        engine.enable_tool("test.write")
        assert engine.check(action_kind="write_file", risk_level=RiskLevel.LOW,
                            tool_name="test.write").verdict == ALLOW

    def test_allowlist_excludes_unlisted_tools(self, engine: PermissionEngine):
        engine.set_tool_allowlist({"test.echo"})
        assert engine.is_tool_enabled("test.echo") is True
        assert engine.is_tool_enabled("test.write") is False

    def test_clearing_allowlist_restores_all(self, engine: PermissionEngine):
        engine.set_tool_allowlist({"test.echo"})
        engine.set_tool_allowlist(None)
        assert engine.is_tool_enabled("test.write") is True


# --------------------------------------------------------------------------
# Registry execution
# --------------------------------------------------------------------------
class TestRegistryExecution:
    def test_read_only_tool_runs_and_self_verifies(self, registry: ToolRegistry):
        result = registry.execute("test.echo", {"text": "hi", "count": 2})
        assert result.success is True
        assert result.output == "hihi"
        assert result.verified is True

    def test_unknown_tool_refused(self, registry: ToolRegistry):
        with pytest.raises(ToolNotFoundError):
            registry.execute("test.nonexistent", {})

    def test_invalid_arguments_refused_before_execution(self, registry: ToolRegistry):
        with pytest.raises(ToolValidationError) as exc:
            registry.execute("test.echo", {"text": "", "count": 99})
        assert "count" in str(exc.value) or "text" in str(exc.value)

    def test_missing_required_argument_refused(self, registry: ToolRegistry):
        with pytest.raises(ToolValidationError):
            registry.execute("test.echo", {})

    def test_medium_risk_needs_approval_in_assisted_mode(self, registry: ToolRegistry):
        with pytest.raises(ApprovalRequiredError):
            registry.execute("test.write", {"target": "out.txt"})

    def test_always_confirm_tool_needs_approval_even_supervised(
        self, registry: ToolRegistry, engine: PermissionEngine
    ):
        engine.set_autonomy_mode(AutonomyMode.SUPERVISED)
        with pytest.raises(ApprovalRequiredError):
            registry.execute("test.delete", {"target": "old.csv"})

    def test_emergency_stop_blocks_execution(
        self, registry: ToolRegistry, engine: PermissionEngine
    ):
        engine.emergency_stop.engage()
        with pytest.raises(EmergencyStopError):
            registry.execute("test.echo", {"text": "hi"})

    def test_disabled_tool_blocked_at_execution(
        self, registry: ToolRegistry, engine: PermissionEngine
    ):
        engine.disable_tool("test.echo")
        with pytest.raises(PermissionDeniedError):
            registry.execute("test.echo", {"text": "hi"})

    def test_raising_tool_becomes_tool_execution_error(self, registry: ToolRegistry):
        with pytest.raises(ToolExecutionError) as exc:
            registry.execute("test.boom", {"text": "x"})
        assert "deliberate failure" in str(exc.value)

    @pytest.mark.slow
    def test_timeout_is_enforced(self, registry: ToolRegistry):
        start = time.perf_counter()
        with pytest.raises(ToolTimeoutError):
            registry.execute("test.slow", {"text": "x"})
        assert time.perf_counter() - start < 4, "timeout did not fire promptly"

    def test_wrong_return_type_rejected(self, registry: ToolRegistry):
        with pytest.raises(ToolExecutionError) as exc:
            registry.execute("test.badreturn", {"text": "x"})
        assert "ToolResult" in str(exc.value)

    def test_dry_run_does_not_execute(
        self, registry: ToolRegistry, engine: PermissionEngine
    ):
        engine.set_autonomy_mode(AutonomyMode.SUPERVISED)
        result = registry.execute(
            "test.write", {"target": "x.txt"},
            context=ToolContext(dry_run=True),
        )
        assert result.success is True
        assert result.verified is False
        assert "dry run" in result.summary.lower()

    def test_cancellation_stops_execution(self, registry: ToolRegistry):
        from pluto.core.exceptions import TaskCancelledError

        event = threading.Event()
        event.set()
        with pytest.raises(TaskCancelledError):
            registry.execute("test.echo", {"text": "hi"},
                             context=ToolContext(cancel_event=event))

    def test_duration_is_recorded(self, registry: ToolRegistry):
        result = registry.execute("test.echo", {"text": "hi"})
        assert result.duration_ms is not None and result.duration_ms >= 0


# --------------------------------------------------------------------------
# Audit integration
# --------------------------------------------------------------------------
class TestAuditIntegration:
    def test_successful_call_is_audited(
        self, registry: ToolRegistry, audit: AuditRepository
    ):
        registry.execute("test.echo", {"text": "hi"})
        entries = audit.list_recent(category="tool")
        assert any(e.tool_name == "test.echo" and e.outcome == "success" for e in entries)

    def test_denied_call_is_audited(
        self, registry: ToolRegistry, engine: PermissionEngine, audit: AuditRepository
    ):
        engine.disable_tool("test.echo")
        with pytest.raises(PermissionDeniedError):
            registry.execute("test.echo", {"text": "hi"})
        assert any(e.outcome == DENY for e in audit.list_recent(category="permission"))

    def test_permission_decisions_are_audited(
        self, engine: PermissionEngine, audit: AuditRepository
    ):
        engine.check(action_kind="read_data", risk_level=RiskLevel.READ_ONLY)
        assert len(audit.list_recent(category="permission")) == 1

    def test_invocation_recorded_with_redacted_arguments(
        self, registry: ToolRegistry, invocations: ToolInvocationRepository, db
    ):
        registry.execute("test.echo", {"text": "sk-ant-api03-ABCDEFGHIJKLMNOPQRS"})
        raw = str(db.fetch_all("SELECT arguments_json FROM tool_invocations;")[0][0])
        assert "sk-ant-api03" not in raw

    def test_mode_change_is_audited(
        self, engine: PermissionEngine, audit: AuditRepository
    ):
        engine.set_autonomy_mode(AutonomyMode.SUPERVISED)
        assert any(
            e.action == "autonomy_mode_changed"
            for e in audit.list_recent(category="security")
        )


# --------------------------------------------------------------------------
# Registry bookkeeping
# --------------------------------------------------------------------------
class TestRegistryBookkeeping:
    def test_duplicate_registration_refused(self, registry: ToolRegistry):
        with pytest.raises(ValueError, match="already registered"):
            registry.register(EchoTool())

    def test_tool_missing_attributes_refused_at_class_creation(self):
        with pytest.raises(TypeError, match="missing required attribute"):

            class Incomplete(Tool):  # type: ignore[type-arg]
                name = "broken"

                def run(self, args, context):  # pragma: no cover
                    return ToolResult.ok()

    def test_schemas_exclude_disabled_tools(
        self, registry: ToolRegistry, engine: PermissionEngine
    ):
        engine.disable_tool("test.echo")
        names = {s["name"] for s in registry.schemas()}
        assert "test.echo" not in names
        assert "test.write" in names

    def test_schema_shape_matches_claude_tool_use(self, registry: ToolRegistry):
        schema = next(s for s in registry.schemas() if s["name"] == "test.echo")
        assert {"name", "description", "input_schema"} == set(schema)
        assert schema["input_schema"]["type"] == "object"

    def test_describe_all_reports_enabled_state(
        self, registry: ToolRegistry, engine: PermissionEngine
    ):
        engine.disable_tool("test.write")
        rows = {row["name"]: row for row in registry.describe_all()}
        assert rows["test.write"]["enabled"] is False
        assert rows["test.echo"]["enabled"] is True

    def test_list_by_category(self, registry: ToolRegistry):
        names = {t.name for t in registry.list_tools(category=ToolCategory.FILESYSTEM)}
        assert names == {"test.write", "test.delete"}

    def test_engine_describe_snapshot(self, engine: PermissionEngine):
        engine.disable_tool("test.write")
        snapshot = engine.describe()
        assert snapshot["autonomy_mode"] == "assisted"
        assert "test.write" in snapshot["disabled_tools"]
        assert "send_email" in snapshot["always_confirm_actions"]

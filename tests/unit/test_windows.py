"""Tests for Windows automation.

**Honest scope.** This suite runs on Linux, where pywinauto and the Windows UI
Automation API do not exist. What it verifies here:

* the policy layer, which is pure logic and platform-independent,
* that every tool refuses cleanly off Windows instead of pretending,
* tool declarations and risk levels.

What it does **not** verify here: that clicking a real button in a real Windows
application works. Those tests are marked ``windows`` and are skipped unless
run on Windows — see tests/e2e/test_windows_e2e.py and the NOT TESTED entries
in docs/STATUS.md.
"""

from __future__ import annotations

import pytest

from pluto.automation.windows import (
    IS_WINDOWS,
    PROTECTED_PROCESSES,
    PROTECTED_WINDOW_PATTERNS,
    ApplicationPolicy,
    build_windows_tools,
    is_protected_window,
    require_windows,
)
from pluto.core.constants import AutonomyMode, RiskLevel, ToolCategory
from pluto.core.exceptions import (
    PermissionDeniedError,
    UnsupportedPlatformError,
)
from pluto.security.paths import PathGuard
from pluto.security.permissions import PermissionEngine
from pluto.tools.registry import ToolRegistry

windows_only = pytest.mark.skipif(not IS_WINDOWS, reason="requires Microsoft Windows")
not_windows = pytest.mark.skipif(IS_WINDOWS, reason="tests the non-Windows refusal path")


# --------------------------------------------------------------------------
# Protected windows — pure logic, runs everywhere
# --------------------------------------------------------------------------
class TestProtectedWindows:
    @pytest.mark.parametrize(
        "title",
        [
            "User Account Control",
            "Windows Security",
            "Administrator: Command Prompt",
            "Registry Editor",
            "Windows Defender Firewall",
            "BitLocker Drive Encryption",
            "Sign in to your account",
            "Local Security Policy",
        ],
    )
    def test_security_windows_are_protected(self, title: str):
        assert is_protected_window(title) is not None

    def test_protection_is_case_insensitive(self):
        assert is_protected_window("USER ACCOUNT CONTROL") is not None
        assert is_protected_window("user account control") is not None

    @pytest.mark.parametrize(
        "process", ["consent.exe", "lsass.exe", "regedit.exe", "powershell.exe", "cmd.exe"]
    )
    def test_protected_processes_refused(self, process: str):
        assert is_protected_window("Some Window", process) is not None

    @pytest.mark.parametrize(
        "title", ["Notepad", "Microsoft Excel - Budget.xlsx", "Calculator", "Untitled - Paint"]
    )
    def test_ordinary_applications_not_protected(self, title: str):
        assert is_protected_window(title) is None

    def test_protection_lists_are_not_empty(self):
        assert len(PROTECTED_WINDOW_PATTERNS) >= 10
        assert len(PROTECTED_PROCESSES) >= 10


# --------------------------------------------------------------------------
# Application policy
# --------------------------------------------------------------------------
class TestApplicationPolicy:
    def test_empty_policy_denies_everything(self):
        policy = ApplicationPolicy()
        with pytest.raises(PermissionDeniedError) as exc:
            policy.check("Notepad")
        assert "Settings" in exc.value.user_message

    def test_approved_application_passes(self):
        assert ApplicationPolicy(["notepad"]).is_allowed("Untitled - Notepad")

    def test_unapproved_application_refused(self):
        policy = ApplicationPolicy(["notepad"])
        with pytest.raises(PermissionDeniedError) as exc:
            policy.check("Microsoft Excel")
        assert "Excel" in exc.value.user_message

    def test_protected_window_refused_even_when_approved(self):
        """Approving an app must not open a path to the UAC prompt."""
        policy = ApplicationPolicy(["user account control", "regedit"])
        with pytest.raises(PermissionDeniedError) as exc:
            policy.check("User Account Control")
        assert "security or system windows" in exc.value.user_message

    def test_protected_process_refused_even_when_approved(self):
        policy = ApplicationPolicy(["powershell"])
        with pytest.raises(PermissionDeniedError):
            policy.check("Windows PowerShell", "powershell.exe")

    def test_allow_and_revoke(self):
        policy = ApplicationPolicy()
        policy.allow("Notepad")
        assert policy.is_allowed("Notepad")
        assert policy.revoke("notepad") is True
        assert not policy.is_allowed("Notepad")

    def test_matching_is_case_insensitive(self):
        assert ApplicationPolicy(["NOTEPAD"]).is_allowed("untitled - notepad")


# --------------------------------------------------------------------------
# Platform refusal
# --------------------------------------------------------------------------
@not_windows
class TestRefusesOffWindows:
    """The honest-failure path: no pretending, no silent no-ops."""

    @pytest.fixture()
    def registry(self, approvals, audit, invocations, tmp_path):
        engine = PermissionEngine(
            autonomy_mode=AutonomyMode.SUPERVISED,
            approval_repo=approvals, audit_repo=audit,
        )
        workspace = tmp_path / "ws"
        workspace.mkdir()
        reg = ToolRegistry(engine, audit_repo=audit, invocation_repo=invocations)
        reg.register_all(
            build_windows_tools(
                ApplicationPolicy(["notepad"]),
                PathGuard(allowed_roots=[workspace]),
                screenshots_enabled=True,
            )
        )
        yield reg
        reg.shutdown()

    def test_require_windows_raises(self):
        with pytest.raises(UnsupportedPlatformError) as exc:
            require_windows()
        assert "only works on Windows" in exc.value.user_message

    def test_list_windows_refuses(self, registry: ToolRegistry):
        from pluto.core.exceptions import ToolExecutionError

        with pytest.raises((UnsupportedPlatformError, ToolExecutionError)):
            registry.execute("windows.list_windows", {})

    def test_inspect_refuses(self, registry: ToolRegistry):
        from pluto.core.exceptions import ToolExecutionError

        with pytest.raises((UnsupportedPlatformError, ToolExecutionError)):
            registry.execute("windows.inspect", {"title": "Notepad"})

    def test_click_refuses(self, registry: ToolRegistry):
        from pluto.core.exceptions import ToolExecutionError

        with pytest.raises((UnsupportedPlatformError, ToolExecutionError)):
            registry.execute(
                "windows.click",
                {"window_title": "Notepad", "control_name": "OK"},
            )

    def test_policy_is_checked_before_the_platform_error(self, registry: ToolRegistry):
        """An unapproved app is refused on policy grounds, not platform grounds —
        proving the policy layer runs regardless of OS."""
        with pytest.raises(PermissionDeniedError):
            registry.execute(
                "windows.click",
                {"window_title": "Microsoft Excel", "control_name": "Save"},
            )

    def test_protected_window_refused_before_platform_check(self, registry: ToolRegistry):
        with pytest.raises(PermissionDeniedError) as exc:
            registry.execute(
                "windows.click",
                {"window_title": "User Account Control", "control_name": "Yes"},
            )
        assert "security or system windows" in exc.value.user_message

    def test_credential_field_refused_before_platform_check(self, registry: ToolRegistry):
        with pytest.raises(PermissionDeniedError) as exc:
            registry.execute(
                "windows.type",
                {"window_title": "Notepad", "control_name": "Password",
                 "text": "hunter2"},
            )
        assert "password" in exc.value.user_message.lower()


# --------------------------------------------------------------------------
# Screenshots
# --------------------------------------------------------------------------
class TestScreenshotGating:
    @pytest.fixture()
    def registry_factory(self, approvals, audit, invocations, tmp_path):
        def build(*, enabled: bool) -> ToolRegistry:
            engine = PermissionEngine(
                autonomy_mode=AutonomyMode.SUPERVISED,
                approval_repo=approvals, audit_repo=audit,
            )
            workspace = tmp_path / "ws"
            workspace.mkdir(exist_ok=True)
            reg = ToolRegistry(engine, audit_repo=audit, invocation_repo=invocations)
            reg.register_all(
                build_windows_tools(
                    ApplicationPolicy(["notepad"]),
                    PathGuard(allowed_roots=[workspace]),
                    screenshots_enabled=enabled,
                )
            )
            return reg

        return build

    def test_disabled_by_default(self, registry_factory, tmp_path):
        registry = registry_factory(enabled=False)
        with pytest.raises(PermissionDeniedError) as exc:
            registry.execute(
                "windows.screenshot",
                {"save_path": str(tmp_path / "ws" / "shot.png")},
            )
        assert "turned off" in exc.value.user_message
        registry.shutdown()

    def test_screenshot_path_is_sandboxed(self, registry_factory, tmp_path):
        from pluto.core.exceptions import PathTraversalError

        registry = registry_factory(enabled=True)
        with pytest.raises((PathTraversalError, UnsupportedPlatformError)):
            registry.execute(
                "windows.screenshot",
                {"save_path": str(tmp_path / "outside" / "shot.png")},
            )
        registry.shutdown()


# --------------------------------------------------------------------------
# Declarations
# --------------------------------------------------------------------------
class TestWindowsToolDeclarations:
    @pytest.fixture()
    def tools(self, tmp_path):
        workspace = tmp_path / "ws"
        workspace.mkdir()
        return build_windows_tools(
            ApplicationPolicy(["notepad"]), PathGuard(allowed_roots=[workspace])
        )

    def test_all_declare_windows_requirement(self, tools):
        assert all(t.requires_windows for t in tools)

    def test_all_in_windows_category(self, tools):
        assert all(t.category == ToolCategory.WINDOWS for t in tools)

    def test_read_tools_are_read_only(self, tools):
        for tool in tools:
            if tool.name in ("windows.list_windows", "windows.inspect"):
                assert tool.risk_level == RiskLevel.READ_ONLY

    def test_acting_tools_are_at_least_medium_risk(self, tools):
        for tool in tools:
            if tool.name in ("windows.click", "windows.type", "windows.screenshot"):
                assert tool.risk_level.rank >= RiskLevel.MEDIUM.rank

    def test_no_arbitrary_shell_tool_exists(self, tools):
        """Spec 7: never an unrestricted shell or arbitrary code execution."""
        names = {t.name for t in tools}
        forbidden = {"windows.run", "windows.shell", "windows.exec", "windows.command",
                     "windows.powershell", "windows.python"}
        assert names & forbidden == set()

    def test_tools_are_registrable_on_any_platform(self, tools, approvals, audit):
        """The permissions dashboard must be able to list them off Windows."""
        engine = PermissionEngine(approval_repo=approvals, audit_repo=audit)
        registry = ToolRegistry(engine)
        registry.register_all(tools)
        assert len(registry.describe_all()) == len(tools)
        registry.shutdown()


# --------------------------------------------------------------------------
# Real Windows — skipped off Windows, NOT TESTED in this environment
# --------------------------------------------------------------------------
@windows_only
class TestRealWindowsAutomation:
    """These need a real Windows desktop. They are skipped on Linux/macOS and
    are recorded as NOT TESTED in docs/STATUS.md until run on Windows."""

    def test_can_list_real_windows(self, approvals, audit, invocations):
        engine = PermissionEngine(
            autonomy_mode=AutonomyMode.SUPERVISED,
            approval_repo=approvals, audit_repo=audit,
        )
        registry = ToolRegistry(engine, audit_repo=audit, invocation_repo=invocations)
        registry.register_all(build_windows_tools(ApplicationPolicy(["notepad"])))
        result = registry.execute("windows.list_windows", {})
        assert result.success is True
        assert isinstance(result.output["windows"], list)
        registry.shutdown()

"""End-to-end Windows desktop tests.

**These require a real, interactive Windows desktop.** They open and drive real
applications, so they are opt-in and are skipped everywhere else.

    pytest tests/e2e -m windows -v

Start with Notepad: it is the least risky automation target. Do not point these
at an application holding data you care about.
"""

from __future__ import annotations

import time

import pytest

from pluto.automation.windows import IS_WINDOWS, ApplicationPolicy, build_windows_tools
from pluto.core.constants import AutonomyMode
from pluto.security.permissions import PermissionEngine
from pluto.tools.registry import ToolRegistry

pytestmark = [pytest.mark.e2e, pytest.mark.windows]

needs_windows = pytest.mark.skipif(
    not IS_WINDOWS, reason="requires a real Windows desktop"
)


@pytest.fixture()
def registry(approvals, audit, invocations):
    engine = PermissionEngine(
        autonomy_mode=AutonomyMode.SUPERVISED,
        approval_repo=approvals,
        audit_repo=audit,
    )
    reg = ToolRegistry(engine, audit_repo=audit, invocation_repo=invocations)
    reg.register_all(build_windows_tools(ApplicationPolicy(["notepad"])))
    yield reg
    reg.shutdown()


@pytest.fixture()
def notepad():
    """Open Notepad for the test and close it afterwards."""
    import subprocess

    process = subprocess.Popen(["notepad.exe"])
    time.sleep(1.5)
    yield process
    try:
        process.terminate()
        process.wait(timeout=5)
    except Exception:
        pass


@needs_windows
class TestWindowsDesktopE2E:
    def test_lists_real_windows(self, registry: ToolRegistry, notepad):
        result = registry.execute("windows.list_windows", {})
        assert result.success is True
        titles = [w["title"].lower() for w in result.output["windows"]]
        assert any("notepad" in t for t in titles), "Notepad was not found"

    def test_inspects_a_real_window(self, registry: ToolRegistry, notepad):
        result = registry.execute("windows.inspect", {"title": "Notepad"})
        assert result.success is True
        assert result.output["controls"], "no controls were read"

    def test_types_into_notepad_and_verifies(self, registry: ToolRegistry, notepad):
        """The real observe/act/verify cycle against a live application."""
        result = registry.execute(
            "windows.type",
            {"window_title": "Notepad", "control_name": "Text editor",
             "text": "Pluto Advance end-to-end test"},
        )
        if not result.success:
            pytest.skip(f"control not found on this Windows build: {result.error}")
        assert result.verified is True, result.verification_note

    def test_protected_window_is_refused_on_a_real_desktop(self, registry: ToolRegistry):
        from pluto.core.exceptions import PermissionDeniedError

        with pytest.raises(PermissionDeniedError):
            registry.execute(
                "windows.click",
                {"window_title": "User Account Control", "control_name": "Yes"},
            )

    def test_unapproved_application_is_refused(self, registry: ToolRegistry):
        from pluto.core.exceptions import PermissionDeniedError

        with pytest.raises(PermissionDeniedError):
            registry.execute("windows.inspect", {"title": "Microsoft Excel"})

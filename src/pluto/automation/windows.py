"""Windows desktop automation.

**Platform status: this module only functions on Windows.** It is written
against pywinauto and the Windows UI Automation API, neither of which exists on
Linux or macOS. On other platforms every tool refuses with a clear message
rather than pretending to work, and the test suite verifies that refusal.

Design, from spec §7 — an observe/decide/act/verify cycle:

1. **Observe** — find the window, read its control tree.
2. **Decide** — match the requested control by name and type, not by screen
   coordinates, so a moved window does not cause a misclick.
3. **Act** — interact with the control through UI Automation.
4. **Verify** — read the control's state back and confirm it changed.

What this module deliberately will not do:

* click through UAC prompts, security dialogs, or windows it cannot identify,
* run an unrestricted shell (there is no arbitrary-command tool here at all),
* interact with an application that is not on the user's approved list.
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass
from typing import Any, ClassVar

from pydantic import BaseModel, Field

from pluto.core.constants import RiskLevel, ToolCategory
from pluto.core.exceptions import (
    PermissionDeniedError,
    UnsupportedPlatformError,
    WindowsAutomationError,
)
from pluto.core.logging_config import get_logger
from pluto.core.models import ToolResult
from pluto.tools.registry import Tool, ToolContext

log = get_logger("automation.windows")

IS_WINDOWS = sys.platform == "win32"

#: Window titles that must never be automated. Matched case-insensitively as
#: substrings against the window title.
PROTECTED_WINDOW_PATTERNS: tuple[str, ...] = (
    "user account control",
    "windows security",
    "windows defender",
    "administrator:",
    "credential manager",
    "sign in to your account",
    "microsoft account",
    "bitlocker",
    "windows update",
    "registry editor",
    "group policy",
    "certificate",
    "firewall",
    "device manager",
    "task scheduler",
    "local security policy",
    "computer management",
)

#: Executables the agent refuses to drive, whatever the allow-list says.
PROTECTED_PROCESSES: frozenset[str] = frozenset(
    {
        "consent.exe", "lsass.exe", "winlogon.exe", "services.exe",
        "regedit.exe", "mmc.exe", "gpedit.msc", "secpol.msc",
        "cmd.exe", "powershell.exe", "pwsh.exe", "wt.exe",
        "taskmgr.exe", "msconfig.exe", "bitlockerwizard.exe",
    }
)


def require_windows() -> None:
    """Raise a clear error when called off Windows."""
    if not IS_WINDOWS:
        raise UnsupportedPlatformError(
            f"Windows automation is not available on {sys.platform}",
            user_message=(
                "Windows automation only works on Windows. This feature is "
                "unavailable on this computer."
            ),
        )


def _load_pywinauto() -> Any:
    require_windows()
    try:
        from pywinauto import Application, Desktop

        return Application, Desktop
    except ImportError as exc:  # pragma: no cover - Windows-only path
        raise WindowsAutomationError(
            "pywinauto is not installed",
            user_message=(
                "Windows automation needs pywinauto. Install it with "
                "'pip install pywinauto' and restart Pluto."
            ),
        ) from exc


def is_protected_window(title: str, process_name: str = "") -> str | None:
    """Return the matching protection rule, or None if the window is fine."""
    lowered = (title or "").lower()
    for pattern in PROTECTED_WINDOW_PATTERNS:
        if pattern in lowered:
            return pattern
    if process_name and process_name.lower() in PROTECTED_PROCESSES:
        return process_name.lower()
    return None


@dataclass
class ApplicationPolicy:
    """Allow-list of applications Pluto may drive. Default deny."""

    allowed: list[str]

    def __init__(self, allowed: list[str] | None = None) -> None:
        self.allowed = [a.lower().strip() for a in (allowed or []) if a.strip()]

    def allow(self, name: str) -> None:
        cleaned = name.lower().strip()
        if cleaned and cleaned not in self.allowed:
            self.allowed.append(cleaned)

    def revoke(self, name: str) -> bool:
        cleaned = name.lower().strip()
        if cleaned in self.allowed:
            self.allowed.remove(cleaned)
            return True
        return False

    def check(self, title: str, process_name: str = "") -> None:
        """Raise unless this window is both approved and not protected."""
        protection = is_protected_window(title, process_name)
        if protection is not None:
            raise PermissionDeniedError(
                f"Refusing to automate a protected window ({protection})",
                user_message=(
                    "Pluto will not interact with security or system windows "
                    "such as UAC prompts, Windows Security, or the registry editor."
                ),
            )

        if not self.allowed:
            raise PermissionDeniedError(
                "No applications are approved",
                user_message=(
                    "No applications are approved for automation. Add one under "
                    "Settings → Permissions first."
                ),
            )

        haystack = f"{title} {process_name}".lower()
        if not any(name in haystack for name in self.allowed):
            raise PermissionDeniedError(
                f"Application not approved: {title}",
                user_message=(
                    f"'{title}' is not on your approved application list. Add it "
                    f"under Settings → Permissions if you want Pluto to use it."
                ),
            )

    def is_allowed(self, title: str, process_name: str = "") -> bool:
        try:
            self.check(title, process_name)
        except PermissionDeniedError:
            return False
        return True


class WindowsTool(Tool[Any]):
    """Base for Windows automation tools."""

    requires_windows: ClassVar[bool] = True

    def __init__(self, policy: ApplicationPolicy) -> None:
        self.policy = policy


# --------------------------------------------------------------------------
# List windows
# --------------------------------------------------------------------------
class ListWindowsArgs(BaseModel):
    visible_only: bool = True


class ListWindowsTool(WindowsTool):
    name: ClassVar[str] = "windows.list_windows"
    description: ClassVar[str] = (
        "List the open application windows on the desktop, so Pluto can work "
        "out which one to use."
    )
    category: ClassVar[ToolCategory] = ToolCategory.WINDOWS
    risk_level: ClassVar[RiskLevel] = RiskLevel.READ_ONLY
    action_kind: ClassVar[str] = "list_windows"
    args_model: ClassVar[type[BaseModel]] = ListWindowsArgs
    timeout_seconds: ClassVar[int] = 30

    def run(self, args: ListWindowsArgs, context: ToolContext) -> ToolResult:
        require_windows()
        _, Desktop = _load_pywinauto()  # pragma: no cover - Windows only

        windows = []  # pragma: no cover - Windows only
        for window in Desktop(backend="uia").windows():  # pragma: no cover
            try:
                title = window.window_text()
                if args.visible_only and not window.is_visible():
                    continue
                if not title:
                    continue
                windows.append(
                    {
                        "title": title,
                        "class_name": window.class_name(),
                        "approved": self.policy.is_allowed(title),
                        "protected": is_protected_window(title) is not None,
                    }
                )
            except Exception as exc:
                log.debug("Could not read a window: %s", exc)

        return ToolResult.ok(  # pragma: no cover - Windows only
            output={"windows": windows},
            summary=f"Found {len(windows)} open window(s)",
            verified=True,
            verification_note="Window list read from the live desktop.",
        )


# --------------------------------------------------------------------------
# Inspect a window
# --------------------------------------------------------------------------
class InspectWindowArgs(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    max_controls: int = Field(default=100, ge=1, le=500)


class InspectWindowTool(WindowsTool):
    name: ClassVar[str] = "windows.inspect"
    description: ClassVar[str] = (
        "Read the controls inside an approved application window: buttons, "
        "text boxes, lists and their current state."
    )
    category: ClassVar[ToolCategory] = ToolCategory.WINDOWS
    risk_level: ClassVar[RiskLevel] = RiskLevel.READ_ONLY
    action_kind: ClassVar[str] = "inspect_window"
    args_model: ClassVar[type[BaseModel]] = InspectWindowArgs
    timeout_seconds: ClassVar[int] = 60

    def run(self, args: InspectWindowArgs, context: ToolContext) -> ToolResult:
        # Policy first: a refusal is about permissions, not about the platform,
        # and it must be reported the same way on every OS.
        self.policy.check(args.title)
        require_windows()
        _, Desktop = _load_pywinauto()  # pragma: no cover - Windows only

        try:  # pragma: no cover - Windows only
            window = Desktop(backend="uia").window(title_re=f".*{args.title}.*")
            window.wait("exists visible", timeout=10)
        except Exception as exc:  # pragma: no cover - Windows only
            return ToolResult.fail(f"Could not find a window matching '{args.title}': {exc}")

        controls = []  # pragma: no cover - Windows only
        for child in window.descendants()[: args.max_controls]:  # pragma: no cover
            try:
                controls.append(
                    {
                        "name": child.window_text(),
                        "type": child.element_info.control_type,
                        "enabled": child.is_enabled(),
                        "visible": child.is_visible(),
                    }
                )
            except Exception:
                continue

        return ToolResult.ok(  # pragma: no cover - Windows only
            output={"title": window.window_text(), "controls": controls},
            summary=f"Read {len(controls)} control(s) from '{args.title}'",
            verified=True,
            verification_note="Control tree read from the live window.",
        )


# --------------------------------------------------------------------------
# Click a control
# --------------------------------------------------------------------------
class ClickControlArgs(BaseModel):
    window_title: str = Field(min_length=1, max_length=300)
    control_name: str = Field(min_length=1, max_length=300)
    control_type: str | None = Field(
        default=None, description="e.g. Button, MenuItem, CheckBox"
    )


class ClickControlTool(WindowsTool):
    name: ClassVar[str] = "windows.click"
    description: ClassVar[str] = (
        "Click a named control in an approved window, identified through UI "
        "Automation rather than screen coordinates."
    )
    category: ClassVar[ToolCategory] = ToolCategory.WINDOWS
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM
    action_kind: ClassVar[str] = "click_control"
    args_model: ClassVar[type[BaseModel]] = ClickControlArgs
    timeout_seconds: ClassVar[int] = 60

    def run(self, args: ClickControlArgs, context: ToolContext) -> ToolResult:
        self.policy.check(args.window_title)
        require_windows()
        _, Desktop = _load_pywinauto()  # pragma: no cover - Windows only

        try:  # pragma: no cover - Windows only
            window = Desktop(backend="uia").window(title_re=f".*{args.window_title}.*")
            window.wait("exists visible enabled", timeout=10)

            # Re-check after resolving the real title: a window can change its
            # title between listing and acting.
            self.policy.check(window.window_text())

            kwargs: dict[str, Any] = {"title": args.control_name}
            if args.control_type:
                kwargs["control_type"] = args.control_type
            control = window.child_window(**kwargs)
            control.wait("exists visible enabled", timeout=10)

            if not control.is_enabled():
                return ToolResult.fail(f"'{args.control_name}' is disabled.")

            control.click_input()
            time.sleep(0.3)
        except PermissionDeniedError:
            raise
        except Exception as exc:  # pragma: no cover - Windows only
            return ToolResult.fail(
                f"Could not click '{args.control_name}': {str(exc)[:200]}"
            )

        return ToolResult.ok(  # pragma: no cover - Windows only
            output={"window": args.window_title, "control": args.control_name},
            summary=f"Clicked '{args.control_name}' in '{args.window_title}'",
        )


# --------------------------------------------------------------------------
# Type into a control
# --------------------------------------------------------------------------
class TypeTextArgs(BaseModel):
    window_title: str = Field(min_length=1, max_length=300)
    control_name: str = Field(min_length=1, max_length=300)
    text: str = Field(max_length=10_000)
    clear_first: bool = True


class TypeTextTool(WindowsTool):
    name: ClassVar[str] = "windows.type"
    description: ClassVar[str] = (
        "Type text into a named text field in an approved window."
    )
    category: ClassVar[ToolCategory] = ToolCategory.WINDOWS
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM
    action_kind: ClassVar[str] = "type_text"
    args_model: ClassVar[type[BaseModel]] = TypeTextArgs
    timeout_seconds: ClassVar[int] = 60

    def run(self, args: TypeTextArgs, context: ToolContext) -> ToolResult:
        self.policy.check(args.window_title)

        # Never type into something that looks like a credential field. This is
        # checked before the platform check so the refusal reads the same way
        # wherever it happens.
        from pluto.automation.browser import _SENSITIVE_FIELD

        if _SENSITIVE_FIELD.search(args.control_name):
            raise PermissionDeniedError(
                f"Refusing to type into '{args.control_name}'",
                user_message=(
                    "Pluto will not type into password or credential fields. "
                    "Please do that yourself."
                ),
            )

        require_windows()
        _, Desktop = _load_pywinauto()  # pragma: no cover - Windows only

        try:  # pragma: no cover - Windows only
            window = Desktop(backend="uia").window(title_re=f".*{args.window_title}.*")
            window.wait("exists visible enabled", timeout=10)
            control = window.child_window(title=args.control_name, control_type="Edit")
            control.wait("exists visible enabled", timeout=10)
            if args.clear_first:
                control.set_edit_text("")
            control.type_keys(args.text, with_spaces=True, set_foreground=True)
            time.sleep(0.2)
            actual = control.window_text()
        except PermissionDeniedError:
            raise
        except Exception as exc:  # pragma: no cover - Windows only
            return ToolResult.fail(f"Could not type into '{args.control_name}': {exc}")

        return ToolResult.ok(  # pragma: no cover - Windows only
            output={"control": args.control_name, "value_after": actual},
            summary=f"Typed into '{args.control_name}'",
        )

    def verify(
        self, args: TypeTextArgs, result: ToolResult, context: ToolContext
    ) -> ToolResult:
        """Read the field back — the observe half of observe/act/verify."""
        if not result.success:
            return result
        actual = result.output.get("value_after", "")
        matched = args.text in actual if args.clear_first else actual.endswith(args.text)
        result.verified = matched
        result.verification_note = (
            "The field contains the text that was typed."
            if matched
            else f"The field reads '{actual[:80]}', which does not match what was typed."
        )
        return result


# --------------------------------------------------------------------------
# Screenshot
# --------------------------------------------------------------------------
class ScreenshotArgs(BaseModel):
    window_title: str | None = Field(
        default=None, description="Omit to capture the whole screen."
    )
    save_path: str = Field(min_length=1, max_length=1000)


class ScreenshotTool(WindowsTool):
    name: ClassVar[str] = "windows.screenshot"
    description: ClassVar[str] = (
        "Capture a screenshot of an approved window, saved into an approved "
        "folder. Only available when screenshots are enabled in Settings."
    )
    category: ClassVar[ToolCategory] = ToolCategory.WINDOWS
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM
    action_kind: ClassVar[str] = "take_screenshot"
    args_model: ClassVar[type[BaseModel]] = ScreenshotArgs
    timeout_seconds: ClassVar[int] = 45

    def __init__(self, policy: ApplicationPolicy, guard: Any, *, enabled: bool = False) -> None:
        super().__init__(policy)
        self.guard = guard
        self.enabled = enabled

    def run(self, args: ScreenshotArgs, context: ToolContext) -> ToolResult:
        if not self.enabled:
            raise PermissionDeniedError(
                "Screenshots are disabled",
                user_message=(
                    "Screenshots are turned off. Enable them under "
                    "Settings → Permissions if you want Pluto to take them."
                ),
            )

        # Sandbox and policy are enforced before the platform check.
        destination = self.guard.validate(args.save_path, for_write=True)
        if args.window_title:
            self.policy.check(args.window_title)
        require_windows()

        try:  # pragma: no cover - Windows only
            _, Desktop = _load_pywinauto()
            if args.window_title:
                window = Desktop(backend="uia").window(
                    title_re=f".*{args.window_title}.*"
                )
                window.wait("exists visible", timeout=10)
                image = window.capture_as_image()
            else:
                from PIL import ImageGrab

                image = ImageGrab.grab()
            destination.parent.mkdir(parents=True, exist_ok=True)
            image.save(destination)
        except PermissionDeniedError:
            raise
        except Exception as exc:  # pragma: no cover - Windows only
            return ToolResult.fail(f"Could not capture the screen: {exc}")

        return ToolResult.ok(  # pragma: no cover - Windows only
            output={"path": str(destination)},
            summary=f"Saved a screenshot to {destination.name}",
        )

    def verify(
        self, args: ScreenshotArgs, result: ToolResult, context: ToolContext
    ) -> ToolResult:
        if not result.success:
            return result
        from pathlib import Path

        path = Path(result.output["path"])
        exists = path.exists() and path.stat().st_size > 0
        result.verified = exists
        result.verification_note = (
            f"Screenshot written ({path.stat().st_size:,} bytes)."
            if exists
            else "No screenshot file was produced."
        )
        return result


def build_windows_tools(
    policy: ApplicationPolicy,
    guard: Any = None,
    *,
    screenshots_enabled: bool = False,
) -> list[Tool[Any]]:
    """Windows automation tools.

    Returned on every platform so the permissions dashboard can list them; on
    non-Windows they refuse at call time with a clear explanation.
    """
    tools: list[Tool[Any]] = [
        ListWindowsTool(policy),
        InspectWindowTool(policy),
        ClickControlTool(policy),
        TypeTextTool(policy),
    ]
    if guard is not None:
        tools.append(ScreenshotTool(policy, guard, enabled=screenshots_enabled))
    return tools

"""GUI tests, run against a real Qt application on the offscreen platform.

These are not "does it import" tests. A ``QApplication`` is created, the real
:class:`MainWindow` is built against a real :class:`PlutoApplication`, every
view is instantiated and navigated to, and interactions are driven through the
widgets themselves.

They are skipped automatically when PySide6 is unavailable.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

# The offscreen platform must be selected before Qt is imported.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6", reason="PySide6 is not installed")

from PySide6.QtWidgets import QApplication

from pluto.core.application import PlutoApplication
from pluto.core.config import Settings
from pluto.core.constants import AutonomyMode, MemoryKind, RiskLevel
from pluto.core.models import ApprovalRequest, MemoryRecord, Task, TaskStep
from pluto.ui.main_window import VIEWS, MainWindow
from pluto.ui.theme import DARK, LIGHT, build_stylesheet, resolve_palette
from pluto.ui.widgets.common import (
    ApprovalCard,
    RiskPill,
    StatusPill,
    TaskProgressCard,
)

pytestmark = pytest.mark.gui


@pytest.fixture(scope="session")
def qt_app() -> QApplication:
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture()
def pluto_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> PlutoApplication:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    settings = Settings(
        _env_file=None,
        data_dir=tmp_path / "data",
        allowed_folders=[workspace],
        theme="dark",
    )
    app = PlutoApplication(settings)
    yield app
    app.shutdown()


@pytest.fixture()
def window(qt_app: QApplication, pluto_app: PlutoApplication) -> MainWindow:
    win = MainWindow(pluto_app)
    yield win
    win._timer.stop()


# --------------------------------------------------------------------------
# Theme
# --------------------------------------------------------------------------
class TestTheme:
    @pytest.mark.parametrize("palette", [DARK, LIGHT])
    def test_stylesheet_generates(self, palette):
        css = build_stylesheet(palette)
        assert "QMainWindow" in css
        assert "#EmergencyStop" in css
        assert palette.primary in css

    def test_both_themes_define_every_colour(self):
        for field in DARK.__dataclass_fields__:
            assert getattr(LIGHT, field), f"light palette is missing {field}"
            assert getattr(DARK, field), f"dark palette is missing {field}"

    def test_resolve_palette_honours_explicit_choice(self):
        assert resolve_palette("light") is LIGHT
        assert resolve_palette("dark") is DARK

    def test_risk_colours_are_distinct(self):
        colours = {
            DARK.risk_read_only, DARK.risk_low, DARK.risk_medium,
            DARK.risk_high, DARK.risk_critical,
        }
        assert len(colours) == 5, "risk levels must be visually distinguishable"


# --------------------------------------------------------------------------
# Window construction
# --------------------------------------------------------------------------
class TestMainWindow:
    def test_window_builds(self, window: MainWindow):
        assert "Pluto Advance 0.5" in window.windowTitle()
        assert window.stack.count() == len(VIEWS)

    def test_every_view_is_constructed(self, window: MainWindow):
        assert set(window.views) == {key for key, _, _ in VIEWS}

    def test_every_view_can_be_shown(self, window: MainWindow):
        """Navigating calls each view's refresh(), so this exercises real code."""
        for key, _, _ in VIEWS:
            window.show_view_by_key(key)
            assert window.stack.currentWidget() is window.views[key]

    def test_emergency_stop_is_always_present(self, window: MainWindow):
        assert window.stop_button.isVisible() or window.stop_button.isEnabled()
        assert "EMERGENCY STOP" in window.stop_button.text()

    def test_emergency_stop_is_reachable_from_every_view(self, window: MainWindow):
        """It lives in the sidebar, so it must never be swapped out with a view."""
        for key, _, _ in VIEWS:
            window.show_view_by_key(key)
            assert window.stop_button.parent() is not None
            assert window.stop_button.isEnabled()

    def test_first_run_lands_on_settings_without_a_key(self, window: MainWindow):
        assert window.app.is_configured is False
        assert window.stack.currentWidget() is window.views["settings"]

    def test_approval_count_shows_in_sidebar(self, window: MainWindow, pluto_app):
        task = Task(title="t", request="r")
        pluto_app.tasks.save(task)
        pluto_app.approvals.save(
            ApprovalRequest(task_id=task.id, action_kind="delete_file",
                            summary="Delete a file", risk_level=RiskLevel.HIGH)
        )
        window._refresh_indicators()
        assert "(1)" in window.nav_buttons["approvals"].text()


# --------------------------------------------------------------------------
# Emergency stop behaviour
# --------------------------------------------------------------------------
class TestEmergencyStopUI:
    def test_engaging_stops_the_application(self, window: MainWindow, pluto_app):
        pluto_app.engage_emergency_stop("test")
        assert pluto_app.emergency_stop.engaged is True

        window._refresh_indicators()
        assert window.stop_button.isChecked() is True
        assert "STOPPED" in window.stop_button.text()

    def test_reset_restores_operation(self, window: MainWindow, pluto_app):
        pluto_app.engage_emergency_stop("test")
        pluto_app.reset_emergency_stop()
        assert pluto_app.emergency_stop.engaged is False

    def test_engaging_cancels_pending_approvals(self, window: MainWindow, pluto_app):
        task = Task(title="t", request="r")
        pluto_app.tasks.save(task)
        pluto_app.approvals.save(
            ApprovalRequest(task_id=task.id, action_kind="send_email", summary="Send")
        )
        assert len(pluto_app.approvals.list_pending()) == 1
        pluto_app.engage_emergency_stop("test")
        assert pluto_app.approvals.list_pending() == []

    def test_stop_is_audited(self, window: MainWindow, pluto_app):
        pluto_app.engage_emergency_stop("test reason")
        entries = pluto_app.audit.list_recent(category="security")
        assert any(e.action == "emergency_stop" for e in entries)


# --------------------------------------------------------------------------
# Widgets render real state
# --------------------------------------------------------------------------
class TestWidgetsReflectRealState:
    def test_progress_counts_only_verified_completions(self, qt_app):
        """A step that ran but was not verified must not count as progress."""
        from pluto.core.constants import TaskStatus

        verified = TaskStep(description="done", ordinal=0)
        verified.status = TaskStatus.COMPLETED
        verified.verified = True

        unverified = TaskStep(description="unproven", ordinal=1)
        unverified.status = TaskStatus.PARTIAL
        unverified.verified = False

        task = Task(title="t", request="r", steps=[verified, unverified])
        card = TaskProgressCard(task, DARK)

        assert card.progress.value() == 1, "unverified step was counted as done"
        assert card.progress.maximum() == 2

    def test_unverified_step_says_so_in_the_ui(self, qt_app):
        from pluto.core.constants import TaskStatus

        step = TaskStep(description="wrote a file", ordinal=0)
        step.status = TaskStatus.PARTIAL
        step.verified = False
        step.verification_note = "No evidence available."

        task = Task(title="t", request="r", steps=[step])
        card = TaskProgressCard(task, DARK)
        row = card._rows[step.id]

        assert row.detail_label.isVisibleTo(card)
        assert "could not be verified" in row.detail_label.text().lower()

    def test_failed_step_shows_its_error(self, qt_app):
        from pluto.core.constants import TaskStatus

        step = TaskStep(description="broke", ordinal=0)
        step.status = TaskStatus.FAILED
        step.error_message = "Disk was full"

        card = TaskProgressCard(Task(title="t", request="r", steps=[step]), DARK)
        assert "Disk was full" in card._rows[step.id].detail_label.text()

    def test_status_pill_colour_tracks_status(self, qt_app):
        pill = StatusPill(DARK, "running")
        running = pill._colour
        pill.set_status("failed")
        assert pill._colour != running
        assert pill._colour == DARK.danger

    def test_risk_pill_colour_tracks_risk(self, qt_app):
        pill = RiskPill(DARK, "low")
        low = pill._colour
        pill.set_risk("critical")
        assert pill._colour != low
        assert pill._colour == DARK.risk_critical

    def test_approval_card_shows_what_is_being_asked(self, qt_app):
        from PySide6.QtWidgets import QLabel

        request = ApprovalRequest(
            action_kind="delete_file",
            tool_name="file.move",
            risk_level=RiskLevel.HIGH,
            summary="Delete Q3-draft.xlsx from Documents",
            details={"arguments": {"path": "Documents/Q3-draft.xlsx"}},
        )
        card = ApprovalCard(request, DARK)
        rendered = " ".join(label.text() for label in card.findChildren(QLabel))

        # The user must be able to see what they are approving: the action, the
        # tool, and the actual file involved.
        assert "Delete File" in rendered
        assert "Q3-draft.xlsx" in rendered
        assert "file.move" in rendered
        assert card.approve_button.isEnabled()
        assert card.deny_button.isEnabled()

    def test_approval_card_redacts_secrets_in_arguments(self, qt_app):
        from PySide6.QtWidgets import QLabel

        request = ApprovalRequest(
            action_kind="submit_form",
            summary="Submit the login form",
            details={"arguments": {"api_key": "sk-ant-api03-ABCDEFGHIJKLMNOP"}},
        )
        card = ApprovalCard(request, DARK)
        rendered = " ".join(label.text() for label in card.findChildren(QLabel))
        assert "sk-ant-api03" not in rendered


# --------------------------------------------------------------------------
# Views against real data
# --------------------------------------------------------------------------
class TestViewsWithRealData:
    def test_permissions_lists_every_tool(self, window: MainWindow, pluto_app):
        view = window.views["permissions"]
        view.refresh()
        assert view.tool_table.rowCount() == len(pluto_app.registry.names)

    def test_permissions_shows_granted_folder(self, window: MainWindow, pluto_app):
        view = window.views["permissions"]
        view.refresh()
        items = [
            view.folder_list.item(i).text() for i in range(view.folder_list.count())
        ]
        assert any("read and write" in text for text in items)

    def test_permissions_warns_when_no_domains_approved(self, window: MainWindow):
        view = window.views["permissions"]
        view.refresh()
        items = [
            view.domain_list.item(i).text() for i in range(view.domain_list.count())
        ]
        assert any("No websites approved" in text for text in items)

    def test_disabling_a_tool_through_the_ui_takes_effect(
        self, window: MainWindow, pluto_app
    ):
        view = window.views["permissions"]
        view._toggle_tool("file.write", False)
        assert pluto_app.permissions.is_tool_enabled("file.write") is False
        view._toggle_tool("file.write", True)
        assert pluto_app.permissions.is_tool_enabled("file.write") is True

    def test_always_confirm_list_is_shown_to_the_user(self, window: MainWindow):
        from PySide6.QtWidgets import QLabel

        view = window.views["permissions"]
        text = " ".join(label.text() for label in view.findChildren(QLabel))
        assert "send email" in text and "make payment" in text

    def test_activity_view_renders_audit_entries(self, window: MainWindow, pluto_app):
        pluto_app.audit.log("tool", "file.read", summary="Read notes.txt")
        view = window.views["activity"]
        view.refresh()
        assert view.audit_table.rowCount() >= 1

    def test_memory_view_loads_without_error(self, window: MainWindow, pluto_app):
        """Regression: Qt unwraps str-enums, which broke the kind lookup."""
        pluto_app.memory.save(
            MemoryRecord(kind=MemoryKind.EPISODIC, content="Tidied the downloads folder")
        )
        view = window.views["memory"]
        view.kind_box.setCurrentIndex(
            list(MemoryKind).index(MemoryKind.EPISODIC)
        )
        view.refresh()
        assert view.table.rowCount() == 1

    def test_memory_view_handles_every_kind(self, window: MainWindow, pluto_app):
        view = window.views["memory"]
        for index in range(view.kind_box.count()):
            view.kind_box.setCurrentIndex(index)
            view.refresh()  # must not raise

    def test_tasks_view_renders_saved_tasks(self, window: MainWindow, pluto_app):
        pluto_app.tasks.save(
            Task(title="Sort invoices", request="sort them",
                 steps=[TaskStep(description="list files")])
        )
        view = window.views["tasks"]
        view.refresh()
        assert len(view._cards) == 1

    def test_settings_masks_the_api_key(self, window: MainWindow, pluto_app):
        view = window.views["settings"]
        view.refresh()
        assert view.key_status.text() == "(not set)"

    def test_diagnostics_contain_no_secrets(self, window: MainWindow, pluto_app):
        view = window.views["settings"]
        view._load_diagnostics()
        text = view.diagnostics.toPlainText().lower()
        assert "sk-ant" not in text
        assert "anthropic_api_key" not in text

    def test_chat_greets_about_the_missing_key(self, window: MainWindow):
        from PySide6.QtWidgets import QLabel

        view = window.views["chat"]
        text = " ".join(label.text() for label in view.findChildren(QLabel))
        assert "API key" in text


# --------------------------------------------------------------------------
# Autonomy mode through the UI
# --------------------------------------------------------------------------
class TestAutonomyModeControl:
    def test_changing_mode_in_chat_updates_the_engine(
        self, window: MainWindow, pluto_app
    ):
        """Regression: Qt unwraps str-enums, so an isinstance check silently
        made this control a no-op."""
        view = window.views["chat"]
        target = list(AutonomyMode).index(AutonomyMode.OBSERVE)
        view.mode_box.setCurrentIndex(target)

        assert pluto_app.permissions.autonomy_mode == AutonomyMode.OBSERVE

    def test_mode_change_is_persisted(self, window: MainWindow, pluto_app):
        view = window.views["chat"]
        view.mode_box.setCurrentIndex(list(AutonomyMode).index(AutonomyMode.WORKFLOW))
        assert pluto_app.preferences.get("autonomy_mode") == "workflow"

    def test_every_mode_is_selectable(self, window: MainWindow, pluto_app):
        view = window.views["chat"]
        for index, mode in enumerate(AutonomyMode):
            view.mode_box.setCurrentIndex(index)
            assert pluto_app.permissions.autonomy_mode == mode

    def test_sidebar_shows_the_current_mode(self, window: MainWindow, pluto_app):
        pluto_app.set_autonomy_mode(AutonomyMode.SUPERVISED)
        window._refresh_indicators()
        assert "Supervised" in window.mode_label.text()


# --------------------------------------------------------------------------
# Application wiring
# --------------------------------------------------------------------------
class TestApplicationWiring:
    def test_tools_are_registered(self, pluto_app: PlutoApplication):
        names = pluto_app.registry.names
        for expected in ("file.list", "file.read", "file.write", "sheet.inspect",
                         "browser.navigate"):
            assert expected in names

    def test_windows_tools_disabled_off_windows(self, pluto_app: PlutoApplication):
        import sys

        if sys.platform == "win32":
            pytest.skip("this asserts the non-Windows path")
        for name in pluto_app.registry.names:
            if pluto_app.registry.get(name).requires_windows:
                assert pluto_app.permissions.is_tool_enabled(name) is False

    def test_status_reports_no_secrets(self, pluto_app: PlutoApplication):
        import json

        text = json.dumps(pluto_app.status(), default=str).lower()
        assert "sk-ant" not in text

    def test_system_prompt_mentions_the_platform_limitation(self, pluto_app):
        import sys

        prompt = pluto_app.system_prompt()
        if sys.platform != "win32":
            assert "not Windows" in prompt

    def test_granting_a_folder_is_audited(self, pluto_app: PlutoApplication, tmp_path):
        extra = tmp_path / "extra"
        extra.mkdir()
        pluto_app.add_folder(str(extra))
        entries = pluto_app.audit.list_recent(category="security")
        assert any(e.action == "folder_granted" for e in entries)

    def test_shutdown_is_idempotent(self, tmp_path, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        app = PlutoApplication(
            Settings(_env_file=None, data_dir=tmp_path / "twice")
        )
        app.shutdown()
        app.shutdown()  # must not raise

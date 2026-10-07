"""The main window.

Layout: a sidebar of views on the left, the active view in the middle, and a
persistent Emergency Stop in the sidebar footer so it is reachable from
anywhere in the application without hunting through menus.

All slow work goes through :func:`run_in_background`, which is what keeps the
Emergency Stop clickable while a task is running.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QButtonGroup,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from pluto.core.application import PlutoApplication
from pluto.core.logging_config import get_logger
from pluto.ui.theme import build_stylesheet, resolve_palette
from pluto.ui.views.activity import ActivityView
from pluto.ui.views.approvals import ApprovalsView
from pluto.ui.views.chat import ChatView
from pluto.ui.views.memory import MemoryView
from pluto.ui.views.permissions import PermissionsView
from pluto.ui.views.settings import SettingsView
from pluto.ui.views.tasks import TasksView

log = get_logger("ui.main_window")

VIEWS: list[tuple[str, str, str]] = [
    ("chat", "Chat", "Talk to Pluto"),
    ("tasks", "Tasks", "Running and recent work"),
    ("approvals", "Approvals", "Decisions Pluto is waiting on"),
    ("activity", "Activity", "Audit log and tool history"),
    ("permissions", "Permissions", "Folders, websites, apps and tools"),
    ("memory", "Memory", "What Pluto remembers"),
    ("settings", "Settings", "API key, model and preferences"),
]


class MainWindow(QMainWindow):
    """Pluto Advance 0.5's main window."""

    emergency_engaged = Signal()

    def __init__(self, app: PlutoApplication) -> None:
        super().__init__()
        self.app = app
        self.palette_colours = resolve_palette(app.settings.theme)

        self.setWindowTitle("Pluto Advance 0.5 — Your Intelligent Digital Operator")
        self.resize(1280, 820)
        self.setMinimumSize(980, 640)
        self.setStyleSheet(build_stylesheet(self.palette_colours))

        self._build_layout()
        self._wire_events()

        # Poll for approvals and status rather than pushing from worker
        # threads: Qt widgets may only be touched from the GUI thread.
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh_indicators)
        self._timer.start(2000)

        self._refresh_indicators()
        self._check_first_run()

    # -- layout -----------------------------------------------------------
    def _build_layout(self) -> None:
        central = QWidget()
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_sidebar())

        self.stack = QStackedWidget()
        self.views: dict[str, QWidget] = {}

        self.views["chat"] = ChatView(self.app, self.palette_colours)
        self.views["tasks"] = TasksView(self.app, self.palette_colours)
        self.views["approvals"] = ApprovalsView(self.app, self.palette_colours)
        self.views["activity"] = ActivityView(self.app, self.palette_colours)
        self.views["permissions"] = PermissionsView(self.app, self.palette_colours)
        self.views["memory"] = MemoryView(self.app, self.palette_colours)
        self.views["settings"] = SettingsView(self.app, self.palette_colours)

        for key, _, _ in VIEWS:
            self.stack.addWidget(self.views[key])

        container = QWidget()
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(22, 20, 22, 14)
        container_layout.addWidget(self.stack)
        root.addWidget(container, stretch=1)

        self.setCentralWidget(central)

        status = QStatusBar()
        self.status_label = QLabel("Ready")
        status.addWidget(self.status_label)
        self.usage_label = QLabel("")
        status.addPermanentWidget(self.usage_label)
        self.setStatusBar(status)

    def _build_sidebar(self) -> QWidget:
        sidebar = QWidget()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(230)

        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(14, 20, 14, 16)
        layout.setSpacing(5)

        brand = QLabel("Pluto Advance")
        brand.setObjectName("BrandName")
        layout.addWidget(brand)

        tagline = QLabel("Your Intelligent Digital Operator")
        tagline.setObjectName("BrandTagline")
        tagline.setWordWrap(True)
        layout.addWidget(tagline)
        layout.addSpacing(18)

        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)
        self.nav_buttons: dict[str, QPushButton] = {}

        for index, (key, label, tooltip) in enumerate(VIEWS):
            button = QPushButton(label)
            button.setObjectName("SidebarButton")
            button.setCheckable(True)
            button.setToolTip(tooltip)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.clicked.connect(lambda _=False, i=index: self._show_view(i))
            self.nav_group.addButton(button, index)
            self.nav_buttons[key] = button
            layout.addWidget(button)

        self.nav_buttons["chat"].setChecked(True)
        layout.addStretch(1)

        self.mode_label = QLabel("")
        self.mode_label.setObjectName("Muted")
        self.mode_label.setWordWrap(True)
        layout.addWidget(self.mode_label)
        layout.addSpacing(8)

        self.stop_button = QPushButton("⬛  EMERGENCY STOP")
        self.stop_button.setObjectName("EmergencyStop")
        self.stop_button.setCheckable(True)
        self.stop_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.stop_button.setToolTip(
            "Cancel pending work and ask running work to stop. "
            "Actions already sent to an outside service cannot be recalled."
        )
        self.stop_button.clicked.connect(self._toggle_emergency_stop)
        layout.addWidget(self.stop_button)

        return sidebar

    def _wire_events(self) -> None:
        """Route orchestrator events into the views, on the GUI thread."""
        events = self.app.events
        chat: ChatView = self.views["chat"]  # type: ignore[assignment]
        tasks: TasksView = self.views["tasks"]  # type: ignore[assignment]

        events.on_task_status = tasks.queue_task_update
        events.on_step_started = lambda t, s: tasks.queue_task_update(t)
        events.on_step_finished = lambda t, s, r: tasks.queue_task_update(t)
        events.on_approval_needed = lambda t, s, a: self._queue_approval_alert()
        events.on_message = chat.queue_system_message

    # -- navigation -------------------------------------------------------
    def _show_view(self, index: int) -> None:
        self.stack.setCurrentIndex(index)
        key = VIEWS[index][0]
        view = self.views[key]
        if hasattr(view, "refresh"):
            try:
                view.refresh()
            except Exception as exc:
                log.warning("Refreshing %s failed: %s", key, exc)

    def show_view_by_key(self, key: str) -> None:
        for index, (candidate, _, _) in enumerate(VIEWS):
            if candidate == key:
                self.nav_buttons[key].setChecked(True)
                self._show_view(index)
                return

    # -- emergency stop ---------------------------------------------------
    def _toggle_emergency_stop(self) -> None:
        if self.app.emergency_stop.engaged:
            self.app.reset_emergency_stop()
            self.stop_button.setText("⬛  EMERGENCY STOP")
            self.stop_button.setChecked(False)
            self.status_label.setText("Emergency Stop reset. Pluto may act again.")
            return

        cancelled = self.app.engage_emergency_stop("Emergency Stop pressed")
        self.stop_button.setText("⬛  STOPPED — click to reset")
        self.stop_button.setChecked(True)
        self.status_label.setText(
            f"Emergency Stop engaged. Signalled {cancelled} running task(s)."
        )
        self.emergency_engaged.emit()

        QMessageBox.information(
            self,
            "Emergency Stop engaged",
            "Pluto has stopped.\n\n"
            f"• Pending work is cancelled\n"
            f"• {cancelled} running task(s) were asked to stop at their next "
            f"checkpoint\n"
            f"• Pending approvals are cancelled\n\n"
            "One limitation, stated plainly: anything already sent to an outside "
            "service — a submitted form, a sent request — cannot be recalled by "
            "this button. Check the Activity view for what completed before the "
            "stop.",
        )

    # -- periodic refresh -------------------------------------------------
    def _refresh_indicators(self) -> None:
        try:
            pending = len(self.app.approvals.list_pending())
        except Exception:
            pending = 0

        button = self.nav_buttons["approvals"]
        button.setText(f"Approvals  ({pending})" if pending else "Approvals")

        mode = self.app.permissions.autonomy_mode
        self.mode_label.setText(f"Mode: {mode.value.replace('_', ' ').title()}")

        usage = self.app.claude.usage
        if usage.request_count:
            self.usage_label.setText(
                f"{usage.total:,} tokens · {usage.request_count} request(s)"
            )

        if self.app.emergency_stop.engaged and not self.stop_button.isChecked():
            self.stop_button.setChecked(True)
            self.stop_button.setText("⬛  STOPPED — click to reset")

        # Views refresh themselves only when visible, to keep this cheap.
        current = self.stack.currentWidget()
        if hasattr(current, "tick"):
            try:
                current.tick()
            except Exception as exc:
                log.debug("View tick failed: %s", exc)

    def _queue_approval_alert(self) -> None:
        self.status_label.setText("Pluto is waiting for your approval.")

    # -- first run --------------------------------------------------------
    def _check_first_run(self) -> None:
        if self.app.is_configured:
            return
        self.show_view_by_key("settings")
        self.status_label.setText("Add your Claude API key to get started.")

    def set_status(self, message: str) -> None:
        self.status_label.setText(message)

    # -- shutdown ---------------------------------------------------------
    def closeEvent(self, event: QCloseEvent) -> None:
        active = self.app.tasks.list_active()
        if active:
            answer = QMessageBox.question(
                self,
                "Work in progress",
                f"{len(active)} task(s) are still running. Closing will ask them "
                f"to stop.\n\nClose anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                event.ignore()
                return

        self._timer.stop()
        try:
            self.app.shutdown()
        except Exception as exc:
            log.error("Shutdown error: %s", exc)
        event.accept()

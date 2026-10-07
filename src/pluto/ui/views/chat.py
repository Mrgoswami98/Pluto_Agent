"""Chat view — the main way in.

Sends a request, shows the plan, and reports what actually happened. Planning
and execution run off the GUI thread so the window, and the Emergency Stop,
stay responsive.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from pluto.core.application import PlutoApplication
from pluto.core.constants import AutonomyMode, TaskStatus
from pluto.core.logging_config import get_logger
from pluto.core.models import Task
from pluto.ui.theme import Palette
from pluto.ui.widgets.common import (
    Card,
    PageHeader,
    TaskProgressCard,
    run_in_background,
)

log = get_logger("ui.chat")


class MessageBubble(Card):
    """One message in the transcript."""

    def __init__(self, author: str, text: str, palette: Palette,
                 *, tone: str = "neutral", parent: QWidget | None = None) -> None:
        super().__init__(parent)

        colour = {
            "user": palette.primary,
            "pluto": palette.text,
            "error": palette.danger,
            "warning": palette.warning,
            "neutral": palette.text_muted,
        }.get(tone, palette.text_muted)

        header = QLabel(author)
        header.setStyleSheet(f"color: {colour}; font-weight: 600; font-size: 12px;")
        self.add(header)

        self.body_label = QLabel(text)
        self.body_label.setWordWrap(True)
        self.body_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        self.add(self.body_label)

    def append_text(self, text: str) -> None:
        self.body_label.setText(self.body_label.text() + text)

    def set_text(self, text: str) -> None:
        self.body_label.setText(text)


class PromptBox(QPlainTextEdit):
    """Input that sends on Enter and newlines on Shift+Enter."""

    submitted = Signal()

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            if event.modifiers() & Qt.KeyboardModifier.ShiftModifier:
                super().keyPressEvent(event)
            else:
                self.submitted.emit()
            return
        super().keyPressEvent(event)


class ChatView(QWidget):
    """Conversation with Pluto."""

    def __init__(self, app: PlutoApplication, palette: Palette,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.app = app
        self.palette_colours = palette
        self._busy = False
        self._current_task: Task | None = None
        self._task_card: TaskProgressCard | None = None
        self._pending_messages: list[tuple[str, str, str]] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        self.header = PageHeader(
            "Chat",
            "Ask in English, Hindi or Hinglish. Pluto plans first, asks before "
            "anything consequential, then reports what it actually did.",
        )
        layout.addWidget(self.header)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        self.transcript_host = QWidget()
        self.transcript = QVBoxLayout(self.transcript_host)
        self.transcript.setContentsMargins(0, 0, 8, 0)
        self.transcript.setSpacing(10)
        self.transcript.addStretch(1)
        self.scroll.setWidget(self.transcript_host)
        layout.addWidget(self.scroll, stretch=1)

        layout.addLayout(self._build_composer())

        # Drain messages queued from worker threads on the GUI thread.
        self._drain_timer = QTimer(self)
        self._drain_timer.timeout.connect(self._drain_messages)
        self._drain_timer.start(250)

        self._greet()

    def _build_composer(self) -> QVBoxLayout:
        wrapper = QVBoxLayout()
        wrapper.setSpacing(8)

        controls = QHBoxLayout()
        controls.addWidget(QLabel("Autonomy:"))

        self.mode_box = QComboBox()
        for mode in AutonomyMode:
            self.mode_box.addItem(mode.value.replace("_", " ").title(), mode)
        self.mode_box.setCurrentIndex(
            list(AutonomyMode).index(self.app.permissions.autonomy_mode)
        )
        self.mode_box.currentIndexChanged.connect(self._on_mode_changed)
        self.mode_box.setToolTip(
            "Observe: look only. Assisted: ask every time. Workflow: run "
            "approved workflows. Supervised: low-risk steps without asking. "
            "High-impact actions always ask."
        )
        controls.addWidget(self.mode_box)
        controls.addStretch(1)

        self.cancel_button = QPushButton("Cancel task")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self._cancel_current)
        controls.addWidget(self.cancel_button)
        wrapper.addLayout(controls)

        composer = QHBoxLayout()
        self.prompt = PromptBox()
        self.prompt.setPlaceholderText(
            "What should Pluto do?  (Enter to send, Shift+Enter for a new line)"
        )
        self.prompt.setFixedHeight(84)
        self.prompt.submitted.connect(self._submit)
        composer.addWidget(self.prompt, stretch=1)

        self.send_button = QPushButton("Send")
        self.send_button.setObjectName("PrimaryButton")
        self.send_button.setFixedHeight(84)
        self.send_button.setFixedWidth(104)
        self.send_button.clicked.connect(self._submit)
        composer.addWidget(self.send_button)

        wrapper.addLayout(composer)
        return wrapper

    # -- transcript -------------------------------------------------------
    def _add_message(self, author: str, text: str, tone: str = "neutral") -> MessageBubble:
        bubble = MessageBubble(author, text, self.palette_colours, tone=tone)
        self.transcript.insertWidget(self.transcript.count() - 1, bubble)
        QTimer.singleShot(40, self._scroll_to_bottom)
        return bubble

    def _scroll_to_bottom(self) -> None:
        bar = self.scroll.verticalScrollBar()
        bar.setValue(bar.maximum())

    def _greet(self) -> None:
        if not self.app.is_configured:
            self._add_message(
                "Pluto",
                "I need a Claude API key before I can do anything. Open Settings "
                "and add one — it is stored in Windows Credential Manager, not in "
                "a file.",
                tone="warning",
            )
            return

        folders = self.app.path_guard.allowed_roots
        if not folders:
            self._add_message(
                "Pluto",
                "Ready. I have no approved folders yet, so I cannot touch files "
                "until you add one under Permissions. Ask me anything meanwhile.",
                tone="neutral",
            )
        else:
            self._add_message(
                "Pluto",
                f"Ready. I can work in {len(folders)} approved folder(s). "
                f"Tell me what you need.",
                tone="neutral",
            )

    def queue_system_message(self, text: str) -> None:
        """Thread-safe: queued here, rendered by the GUI timer."""
        self._pending_messages.append(("Pluto", text, "neutral"))

    def _drain_messages(self) -> None:
        while self._pending_messages:
            author, text, tone = self._pending_messages.pop(0)
            self._add_message(author, text, tone)

    # -- sending ----------------------------------------------------------
    def _submit(self) -> None:
        request = self.prompt.toPlainText().strip()
        if not request or self._busy:
            return

        if not self.app.is_configured:
            self._add_message(
                "Pluto",
                "I still need a Claude API key. Open Settings to add one.",
                tone="warning",
            )
            return

        if self.app.emergency_stop.engaged:
            self._add_message(
                "Pluto",
                "Emergency Stop is engaged. Reset it before I can do anything.",
                tone="warning",
            )
            return

        self.prompt.clear()
        self._add_message("You", request, tone="user")
        self._set_busy(True)
        self._add_message("Pluto", "Working out a plan…", tone="neutral")

        run_in_background(
            self._plan_and_run,
            request,
            on_success=self._on_finished,
            on_error=self._on_error,
        )

    def _plan_and_run(self, request: str) -> dict[str, Any]:
        """Runs on a worker thread. Touches no widgets."""
        result = self.app.planner.plan(
            request,
            system_prompt=self.app.system_prompt(),
            autonomy_mode=self.app.permissions.autonomy_mode,
            cancel_event=self.app.emergency_stop.event,
        )

        if result.needs_clarification:
            return {"kind": "clarification", "question": result.clarification_needed}

        task = result.task
        assert task is not None
        self.app.tasks.save(task)
        self._current_task = task

        report = self.app.orchestrator.execute(task)
        return {
            "kind": "report",
            "task": task,
            "report": report,
            "corrections": result.corrections,
        }

    # -- results ----------------------------------------------------------
    def _on_finished(self, payload: dict[str, Any]) -> None:
        self._set_busy(False)

        if payload["kind"] == "clarification":
            self._add_message("Pluto", payload["question"], tone="warning")
            return

        task: Task = payload["task"]
        report = payload["report"]

        if payload.get("corrections"):
            self._add_message(
                "Pluto",
                "I adjusted the plan before running it:\n• "
                + "\n• ".join(payload["corrections"]),
                tone="warning",
            )

        if self._task_card is None:
            self._task_card = TaskProgressCard(task, self.palette_colours)
            self.transcript.insertWidget(self.transcript.count() - 1, self._task_card)
        self._task_card.refresh(task)
        self._task_card = None

        tone = {
            TaskStatus.COMPLETED: "pluto",
            TaskStatus.PARTIAL: "warning",
            TaskStatus.FAILED: "error",
            TaskStatus.CANCELLED: "warning",
            TaskStatus.AWAITING_APPROVAL: "warning",
        }.get(task.status, "neutral")

        self._add_message("Pluto", self._describe(task, report), tone=tone)
        QTimer.singleShot(60, self._scroll_to_bottom)

    @staticmethod
    def _describe(task: Task, report: Any) -> str:
        """Plain-language outcome. Never claims more than the report supports."""
        if task.status == TaskStatus.AWAITING_APPROVAL:
            return (
                "I have paused — some steps need your approval before I can run "
                "them. Open the Approvals view to decide."
            )
        if task.status == TaskStatus.CANCELLED:
            return "Stopped. " + report.summary_line()
        if task.status == TaskStatus.COMPLETED:
            return "Done. " + report.summary_line()
        if task.status == TaskStatus.PARTIAL:
            return (
                "Partly done — I want to be accurate about this rather than say "
                "it all worked.\n" + report.summary_line()
            )
        return "That did not work. " + report.summary_line()

    def _on_error(self, message: str, exc: Exception) -> None:
        self._set_busy(False)
        self._add_message("Pluto", message, tone="error")
        log.warning("Chat task failed: %s", exc)

    # -- state ------------------------------------------------------------
    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        self.send_button.setEnabled(not busy)
        self.send_button.setText("Working…" if busy else "Send")
        self.prompt.setReadOnly(busy)
        self.cancel_button.setEnabled(busy)

    def _cancel_current(self) -> None:
        if self._current_task is not None:
            self.app.orchestrator.cancel(self._current_task.id)
            self._add_message("Pluto", "Cancelling…", tone="warning")

    def _on_mode_changed(self, index: int) -> None:
        # Qt returns str-subclass enums as plain strings, so an isinstance check
        # against AutonomyMode would silently never fire. Coerce instead.
        raw = self.mode_box.itemData(index)
        try:
            mode = AutonomyMode(raw)
        except (ValueError, TypeError):
            log.warning("Ignoring unrecognised autonomy mode from the combo: %r", raw)
            return

        self.app.set_autonomy_mode(mode)
        self._add_message(
            "Pluto",
            f"Autonomy mode is now {mode.value.replace('_', ' ')}. "
            + (
                "I will not change anything in this mode."
                if mode == AutonomyMode.OBSERVE
                else "High-impact actions still need your confirmation."
            ),
            tone="neutral",
        )

    def refresh(self) -> None:
        current = self.app.permissions.autonomy_mode
        index = list(AutonomyMode).index(current)
        if self.mode_box.currentIndex() != index:
            self.mode_box.blockSignals(True)
            self.mode_box.setCurrentIndex(index)
            self.mode_box.blockSignals(False)

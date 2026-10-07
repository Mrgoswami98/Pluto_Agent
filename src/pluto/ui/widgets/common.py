"""Reusable widgets.

Deliberately small and state-driven: every widget renders what it is given and
nothing more. No widget here fabricates a success state — a progress bar moves
because a step completed, and a status pill reads what the task actually says.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QObject, QRunnable, Qt, QThreadPool, Signal, Slot
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from pluto.core.models import ApprovalRequest, Task, TaskStep
from pluto.security.secrets import redact, redact_mapping
from pluto.ui.theme import Palette, risk_colour, status_colour


class Card(QFrame):
    """A bordered panel."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Card")
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(16, 16, 16, 16)
        self._layout.setSpacing(10)

    def body(self) -> QVBoxLayout:
        return self._layout

    def add(self, widget: QWidget) -> QWidget:
        self._layout.addWidget(widget)
        return widget


class Pill(QLabel):
    """A small coloured label for a status or risk level."""

    def __init__(self, text: str, colour: str, parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self.set_colour(colour)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)

    def set_colour(self, colour: str) -> None:
        self._colour = colour
        self.setStyleSheet(
            f"background-color: {colour}22; color: {colour};"
            f"border: 1px solid {colour}66; border-radius: 9px;"
            f"padding: 2px 9px; font-size: 11px; font-weight: 600;"
        )

    def update_state(self, text: str, colour: str) -> None:
        self.setText(text)
        self.set_colour(colour)


class StatusPill(Pill):
    """Shows a task or step status with its canonical colour."""

    def __init__(self, palette: Palette, status: str = "pending",
                 parent: QWidget | None = None) -> None:
        self._palette = palette
        super().__init__(status.replace("_", " "), status_colour(palette, status), parent)

    def set_status(self, status: str) -> None:
        self.update_state(
            status.replace("_", " "), status_colour(self._palette, status)
        )


class RiskPill(Pill):
    """Shows a risk level with its canonical colour."""

    def __init__(self, palette: Palette, risk: str = "low",
                 parent: QWidget | None = None) -> None:
        self._palette = palette
        super().__init__(risk.replace("_", " "), risk_colour(palette, risk), parent)

    def set_risk(self, risk: str) -> None:
        self.update_state(risk.replace("_", " "), risk_colour(self._palette, risk))


class PageHeader(QWidget):
    """Title and subtitle at the top of a view."""

    def __init__(self, title: str, subtitle: str = "",
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 6)
        layout.setSpacing(3)

        self.title_label = QLabel(title)
        self.title_label.setObjectName("PageTitle")
        layout.addWidget(self.title_label)

        self.subtitle_label = QLabel(subtitle)
        self.subtitle_label.setObjectName("PageSubtitle")
        self.subtitle_label.setWordWrap(True)
        self.subtitle_label.setVisible(bool(subtitle))
        layout.addWidget(self.subtitle_label)

    def set_subtitle(self, text: str) -> None:
        self.subtitle_label.setText(text)
        self.subtitle_label.setVisible(bool(text))


class StepRow(QWidget):
    """One step inside the task progress view.

    Shows the real verification state, because "ran" and "verified" are
    different things and the user needs to see which one happened.
    """

    def __init__(self, step: TaskStep, palette: Palette,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._palette = palette
        self.step = step

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 5, 0, 5)
        layout.setSpacing(10)

        self.index_label = QLabel(f"{step.ordinal + 1}.")
        self.index_label.setObjectName("Muted")
        self.index_label.setFixedWidth(22)
        layout.addWidget(self.index_label)

        text_column = QVBoxLayout()
        text_column.setSpacing(2)

        self.description_label = QLabel(step.description)
        self.description_label.setWordWrap(True)
        text_column.addWidget(self.description_label)

        self.detail_label = QLabel("")
        self.detail_label.setObjectName("Muted")
        self.detail_label.setWordWrap(True)
        self.detail_label.setVisible(False)
        text_column.addWidget(self.detail_label)

        layout.addLayout(text_column, stretch=1)

        self.risk_pill = RiskPill(palette, step.risk_level.value)
        layout.addWidget(self.risk_pill)

        self.status_pill = StatusPill(palette, step.status.value)
        layout.addWidget(self.status_pill)

        self.refresh(step)

    def refresh(self, step: TaskStep) -> None:
        self.step = step
        self.status_pill.set_status(step.status.value)
        self.risk_pill.set_risk(step.risk_level.value)

        detail = ""
        if step.error_message:
            detail = step.error_message
        elif step.status.value == "partial" and not step.verified:
            detail = (
                f"Ran, but could not be verified. {step.verification_note or ''}".strip()
            )
        elif step.verified and step.verification_note:
            detail = step.verification_note

        self.detail_label.setText(detail)
        self.detail_label.setVisible(bool(detail))


class TaskProgressCard(Card):
    """Live progress for one task."""

    def __init__(self, task: Task, palette: Palette,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._palette = palette
        self.task = task
        self._rows: dict[str, StepRow] = {}

        header = QHBoxLayout()
        self.title_label = QLabel(task.title)
        self.title_label.setObjectName("SectionTitle")
        self.title_label.setWordWrap(True)
        header.addWidget(self.title_label, stretch=1)

        self.status_pill = StatusPill(palette, task.status.value)
        header.addWidget(self.status_pill)
        self.body().addLayout(header)

        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setRange(0, max(1, len(task.steps)))
        self.body().addWidget(self.progress)

        self.summary_label = QLabel("")
        self.summary_label.setObjectName("Muted")
        self.summary_label.setWordWrap(True)
        self.body().addWidget(self.summary_label)

        self.steps_container = QVBoxLayout()
        self.steps_container.setSpacing(0)
        self.body().addLayout(self.steps_container)

        for step in task.steps:
            row = StepRow(step, palette)
            self._rows[step.id] = row
            self.steps_container.addWidget(row)

        self.refresh(task)

    def refresh(self, task: Task) -> None:
        """Re-render from the task's real state."""
        self.task = task
        self.title_label.setText(task.title)
        self.status_pill.set_status(task.status.value)

        self.progress.setRange(0, max(1, len(task.steps)))
        # Progress counts verified completions only.
        self.progress.setValue(task.completed_steps)

        if task.result_summary:
            self.summary_label.setText(task.result_summary)
            self.summary_label.setVisible(True)
        else:
            self.summary_label.setVisible(False)

        for step in task.steps:
            row = self._rows.get(step.id)
            if row is None:
                row = StepRow(step, self._palette)
                self._rows[step.id] = row
                self.steps_container.addWidget(row)
            else:
                row.refresh(step)


class ApprovalCard(Card):
    """One pending approval, with the detail needed to decide."""

    approved = Signal(str)
    denied = Signal(str)

    def __init__(self, request: ApprovalRequest, palette: Palette,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.request = request

        top = QHBoxLayout()
        action_label = QLabel(request.action_kind.replace("_", " ").title())
        action_label.setObjectName("SectionTitle")
        top.addWidget(action_label, stretch=1)
        top.addWidget(RiskPill(palette, request.risk_level.value))
        self.body().addLayout(top)

        summary = QLabel(request.summary)
        summary.setWordWrap(True)
        self.body().addWidget(summary)

        if request.tool_name:
            tool_label = QLabel(f"Tool: {request.tool_name}")
            tool_label.setObjectName("Muted")
            self.body().addWidget(tool_label)

        details = request.details.get("arguments")
        if details:
            detail_label = QLabel(_format_arguments(details))
            detail_label.setObjectName("Muted")
            detail_label.setWordWrap(True)
            detail_label.setFont(QFont("Consolas", 10))
            self.body().addWidget(detail_label)

        if request.expires_at is not None:
            expiry = QLabel(
                f"Expires at {request.expires_at.astimezone().strftime('%H:%M')}"
            )
            expiry.setObjectName("Muted")
            self.body().addWidget(expiry)

        buttons = QHBoxLayout()
        buttons.addStretch(1)

        self.deny_button = QPushButton("Deny")
        self.deny_button.clicked.connect(lambda: self.denied.emit(self.request.id))
        buttons.addWidget(self.deny_button)

        self.approve_button = QPushButton("Approve")
        self.approve_button.setObjectName("ApproveButton")
        self.approve_button.clicked.connect(lambda: self.approved.emit(self.request.id))
        buttons.addWidget(self.approve_button)

        self.body().addLayout(buttons)

    def set_resolved(self, text: str) -> None:
        self.approve_button.setEnabled(False)
        self.deny_button.setEnabled(False)
        self.approve_button.setText(text)


class EmptyState(QWidget):
    """Shown when a list has nothing in it."""

    def __init__(self, message: str, hint: str = "",
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(6)

        label = QLabel(message)
        label.setObjectName("SectionTitle")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(label)

        if hint:
            hint_label = QLabel(hint)
            hint_label.setObjectName("Muted")
            hint_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            hint_label.setWordWrap(True)
            layout.addWidget(hint_label)


# --------------------------------------------------------------------------
# Background work
# --------------------------------------------------------------------------
class WorkerSignals(QObject):
    finished = Signal(object)
    failed = Signal(str, object)
    progress = Signal(object)


class Worker(QRunnable):
    """Runs a callable off the GUI thread.

    Everything slow — planning, tool execution, API calls — goes through this,
    so the window never freezes and the Emergency Stop button stays clickable.
    That last point is why this class exists at all.
    """

    def __init__(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
        super().__init__()
        self.signals = WorkerSignals()
        self._fn = fn
        self._args = args
        self._kwargs = kwargs

    @Slot()
    def run(self) -> None:
        try:
            result = self._fn(*self._args, **self._kwargs)
        except Exception as exc:
            message = getattr(exc, "user_message", None) or str(exc)
            self.signals.failed.emit(str(message), exc)
        else:
            self.signals.finished.emit(result)


def run_in_background(
    fn: Callable[..., Any],
    *args: Any,
    on_success: Callable[[Any], None] | None = None,
    on_error: Callable[[str, Exception], None] | None = None,
    **kwargs: Any,
) -> Worker:
    """Submit *fn* to the global thread pool and wire up the callbacks."""
    worker = Worker(fn, *args, **kwargs)
    if on_success is not None:
        worker.signals.finished.connect(on_success)
    if on_error is not None:
        worker.signals.failed.connect(on_error)
    QThreadPool.globalInstance().start(worker)
    return worker


def _format_arguments(arguments: Any, limit: int = 400) -> str:
    """Render tool arguments for an approval card.

    Redacts at the point of display as well as at the point of storage: an
    approval built in memory has not been through the repository, so this is
    the last place to catch a credential before it reaches the screen.
    """
    if isinstance(arguments, dict):
        safe = redact_mapping(arguments)
        text = "\n".join(f"{key}: {value}" for key, value in safe.items())
    else:
        text = redact(str(arguments))
    return text if len(text) <= limit else text[:limit] + "…"

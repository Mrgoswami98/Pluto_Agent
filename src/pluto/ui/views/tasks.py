"""Tasks view — running and recent work."""

from __future__ import annotations

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QHBoxLayout, QPushButton, QScrollArea, QVBoxLayout, QWidget

from pluto.core.application import PlutoApplication
from pluto.core.logging_config import get_logger
from pluto.core.models import Task
from pluto.ui.theme import Palette
from pluto.ui.widgets.common import EmptyState, PageHeader, TaskProgressCard

log = get_logger("ui.tasks")


class TasksView(QWidget):
    """Live task progress plus recent history."""

    def __init__(self, app: PlutoApplication, palette: Palette,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.app = app
        self.palette_colours = palette
        self._cards: dict[str, TaskProgressCard] = {}
        #: Updates arrive from worker threads; the GUI timer drains them.
        self._queued: dict[str, Task] = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        header_row = QHBoxLayout()
        header_row.addWidget(
            PageHeader(
                "Tasks",
                "Progress counts steps that completed AND verified. A step that "
                "ran without evidence shows as partial, not done.",
            ),
            stretch=1,
        )
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.refresh)
        header_row.addWidget(self.refresh_button)
        layout.addLayout(header_row)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        self.host = QWidget()
        self.list_layout = QVBoxLayout(self.host)
        self.list_layout.setContentsMargins(0, 0, 8, 0)
        self.list_layout.setSpacing(10)
        self.list_layout.addStretch(1)
        self.scroll.setWidget(self.host)
        layout.addWidget(self.scroll, stretch=1)

        self.empty = EmptyState(
            "No tasks yet",
            "Ask Pluto to do something in the Chat view and it will appear here.",
        )
        layout.addWidget(self.empty)

        self._drain_timer = QTimer(self)
        self._drain_timer.timeout.connect(self._drain)
        self._drain_timer.start(400)

        self.refresh()

    def queue_task_update(self, task: Task) -> None:
        """Called from worker threads. Never touches widgets directly."""
        self._queued[task.id] = task

    def _drain(self) -> None:
        if not self._queued:
            return
        pending, self._queued = self._queued, {}
        for task in pending.values():
            self._upsert(task)

    def _upsert(self, task: Task) -> None:
        card = self._cards.get(task.id)
        if card is None:
            card = TaskProgressCard(task, self.palette_colours)
            self._cards[task.id] = card
            self.list_layout.insertWidget(0, card)
        else:
            card.refresh(task)
        self.empty.setVisible(False)
        self.scroll.setVisible(True)

    def refresh(self) -> None:
        try:
            tasks = self.app.tasks.list_recent(limit=25)
        except Exception as exc:
            log.error("Could not load tasks: %s", exc)
            return

        self._clear()
        self.empty.setVisible(not tasks)
        self.scroll.setVisible(bool(tasks))

        for task in tasks:
            card = TaskProgressCard(task, self.palette_colours)
            self._cards[task.id] = card
            self.list_layout.insertWidget(self.list_layout.count() - 1, card)

    def tick(self) -> None:
        self._drain()

    def _clear(self) -> None:
        self._cards.clear()
        while self.list_layout.count() > 1:
            item = self.list_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

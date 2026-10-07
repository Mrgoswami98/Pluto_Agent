"""Memory view — see, export and delete what Pluto remembers."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from pluto.core.application import PlutoApplication
from pluto.core.constants import MemoryKind
from pluto.core.logging_config import get_logger
from pluto.ui.theme import Palette
from pluto.ui.widgets.common import PageHeader

log = get_logger("ui.memory")

KIND_DESCRIPTIONS = {
    MemoryKind.WORKING: "Scratch notes for the task Pluto is doing right now.",
    MemoryKind.EPISODIC: "Summaries of tasks Pluto has completed before.",
    MemoryKind.PREFERENCE: "Things you told Pluto to remember about how you work.",
    MemoryKind.PROCEDURAL: "Reusable steps Pluto learned for recurring jobs.",
}


class MemoryView(QWidget):
    """Full control over stored memory, including deletion."""

    def __init__(self, app: PlutoApplication, palette: Palette,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.app = app
        self.palette_colours = palette

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        layout.addWidget(
            PageHeader(
                "Memory",
                "Everything Pluto remembers between sessions, and controls to "
                "export or delete any of it. Secrets are stripped before storage.",
            )
        )

        controls = QHBoxLayout()
        controls.addWidget(QLabel("Kind:"))
        self.kind_box = QComboBox()
        for kind in MemoryKind:
            self.kind_box.addItem(kind.value.title(), kind)
        self.kind_box.currentIndexChanged.connect(self.refresh)
        controls.addWidget(self.kind_box)

        self.description_label = QLabel("")
        self.description_label.setObjectName("Muted")
        controls.addWidget(self.description_label, stretch=1)

        self.export_button = QPushButton("Export all")
        self.export_button.clicked.connect(self._export)
        controls.addWidget(self.export_button)

        self.delete_button = QPushButton("Delete selected")
        self.delete_button.clicked.connect(self._delete_selected)
        controls.addWidget(self.delete_button)

        self.forget_button = QPushButton("Forget everything")
        self.forget_button.setObjectName("DangerButton")
        self.forget_button.clicked.connect(self._forget_all)
        controls.addWidget(self.forget_button)
        layout.addLayout(controls)

        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(
            ["Created", "Key", "Content", "Used", "Pinned"]
        )
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch
        )
        layout.addWidget(self.table, stretch=1)

        self.status_label = QLabel("")
        self.status_label.setObjectName("Muted")
        layout.addWidget(self.status_label)

        self.refresh()

    def refresh(self) -> None:
        # Qt stores str-subclass enums as plain strings in item data, so coerce
        # back to the enum rather than assuming what comes out.
        raw_kind = self.kind_box.currentData()
        try:
            kind = MemoryKind(raw_kind) if raw_kind else MemoryKind.EPISODIC
        except ValueError:
            kind = MemoryKind.EPISODIC
        self.description_label.setText(KIND_DESCRIPTIONS.get(kind, ""))

        try:
            records = self.app.memory.list_by_kind(kind, limit=300)
        except Exception as exc:
            log.error("Could not load memory: %s", exc)
            return

        self.table.setRowCount(len(records))
        for row, record in enumerate(records):
            created = record.created_at.astimezone().strftime("%d %b %Y %H:%M")
            cells = [
                created,
                record.key or "—",
                record.content[:300],
                str(record.use_count),
                "yes" if record.pinned else "",
            ]
            for column, text in enumerate(cells):
                item = QTableWidgetItem(str(text))
                if column == 0:
                    item.setData(32, record.id)  # Qt.UserRole
                self.table.setItem(row, column, item)
        self.table.resizeColumnsToContents()
        self.table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch
        )

        self.status_label.setText(
            f"{len(records)} record(s) of this kind. Pinned records are kept "
            f"until you delete them explicitly."
        )

    def _delete_selected(self) -> None:
        row = self.table.currentRow()
        if row < 0:
            return
        item = self.table.item(row, 0)
        record_id = item.data(32) if item else None
        if not record_id:
            return
        if not self.app.memory.delete(record_id):
            QMessageBox.information(
                self, "Pinned record",
                "That record is pinned. Unpin it before deleting.",
            )
        self.refresh()

    def _forget_all(self) -> None:
        answer = QMessageBox.question(
            self,
            "Forget everything?",
            "This permanently deletes every memory record, including pinned "
            "ones and your saved preferences about how Pluto should work.\n\n"
            "Task history and the audit log are not affected.\n\nContinue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        removed = self.app.memory.delete_all()
        self.app.audit.log(
            "privacy", "memory_cleared",
            summary=f"User deleted all memory ({removed} records)",
        )
        QMessageBox.information(self, "Memory cleared", f"Deleted {removed} record(s).")
        self.refresh()

    def _export(self) -> None:
        import json
        from pathlib import Path

        from PySide6.QtWidgets import QFileDialog

        path, _ = QFileDialog.getSaveFileName(
            self, "Export memory", "pluto-memory.json", "JSON (*.json)"
        )
        if not path:
            return
        try:
            Path(path).write_text(
                json.dumps(self.app.memory.export_all(), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception as exc:
            QMessageBox.warning(self, "Export failed", str(exc))
            return
        QMessageBox.information(self, "Exported", f"Memory written to {path}")

    def tick(self) -> None:
        pass

"""Activity view — audit log and tool history."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from pluto.core.application import PlutoApplication
from pluto.core.logging_config import get_logger
from pluto.ui.theme import Palette
from pluto.ui.widgets.common import PageHeader

log = get_logger("ui.activity")


class ActivityView(QWidget):
    """The audit trail, exactly as recorded — nothing is hidden or prettified."""

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
                "Activity",
                "Everything Pluto did, including what it refused to do. Secrets "
                "are redacted before anything is written here.",
            )
        )

        controls = QHBoxLayout()
        controls.addWidget(QLabel("Category:"))
        self.category_box = QComboBox()
        self.category_box.addItem("All", None)
        for category in ("permission", "tool", "security", "task", "application"):
            self.category_box.addItem(category.title(), category)
        self.category_box.currentIndexChanged.connect(self.refresh)
        controls.addWidget(self.category_box)
        controls.addStretch(1)

        self.export_button = QPushButton("Export audit log")
        self.export_button.clicked.connect(self._export)
        controls.addWidget(self.export_button)

        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.refresh)
        controls.addWidget(self.refresh_button)
        layout.addLayout(controls)

        self.tabs = QTabWidget()
        self.audit_table = self._make_table(
            ["Time", "Category", "Action", "Outcome", "Summary"]
        )
        self.tabs.addTab(self.audit_table, "Audit log")

        self.tool_table = self._make_table(
            ["Tool", "Calls", "Successes", "Average ms"]
        )
        self.tabs.addTab(self.tool_table, "Tool usage")
        layout.addWidget(self.tabs, stretch=1)

        self.status_label = QLabel("")
        self.status_label.setObjectName("Muted")
        layout.addWidget(self.status_label)

        self.refresh()

    @staticmethod
    def _make_table(headers: list[str]) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setSectionResizeMode(
            len(headers) - 1, QHeaderView.ResizeMode.Stretch
        )
        return table

    def refresh(self) -> None:
        category = self.category_box.currentData()
        try:
            entries = self.app.audit.list_recent(limit=400, category=category)
        except Exception as exc:
            log.error("Could not load the audit log: %s", exc)
            return

        self.audit_table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            local_time = entry.occurred_at.astimezone().strftime("%d %b %H:%M:%S")
            cells = [
                local_time,
                entry.category,
                entry.action,
                entry.outcome,
                entry.summary,
            ]
            for column, text in enumerate(cells):
                item = QTableWidgetItem(str(text))
                if column == 3:
                    colour = {
                        "success": self.palette_colours.success,
                        "allow": self.palette_colours.success,
                        "denied": self.palette_colours.danger,
                        "deny": self.palette_colours.danger,
                        "error": self.palette_colours.danger,
                        "timeout": self.palette_colours.warning,
                        "require_approval": self.palette_colours.warning,
                        "awaiting_approval": self.palette_colours.warning,
                    }.get(str(text))
                    if colour:
                        item.setForeground(Qt.GlobalColor.white)
                        item.setData(Qt.ItemDataRole.ForegroundRole, None)
                        item.setToolTip(str(text))
                self.audit_table.setItem(row, column, item)
        self.audit_table.resizeColumnsToContents()

        try:
            usage = self.app.invocations.usage_summary()
        except Exception:
            usage = []
        self.tool_table.setRowCount(len(usage))
        for row, record in enumerate(usage):
            average = record.get("avg_ms")
            cells = [
                record["tool_name"],
                record["calls"],
                record["successes"],
                f"{average:.0f}" if average else "—",
            ]
            for column, text in enumerate(cells):
                self.tool_table.setItem(row, column, QTableWidgetItem(str(text)))
        self.tool_table.resizeColumnsToContents()

        self.status_label.setText(
            f"{len(entries)} audit entries shown · {self.app.audit.count():,} total"
        )

    def _export(self) -> None:
        from PySide6.QtWidgets import QFileDialog, QMessageBox

        path, _ = QFileDialog.getSaveFileName(
            self, "Export audit log", "pluto-audit.jsonl", "JSON Lines (*.jsonl)"
        )
        if not path:
            return
        try:
            from pathlib import Path

            Path(path).write_text(self.app.audit.export_jsonl(), encoding="utf-8")
        except Exception as exc:
            QMessageBox.warning(self, "Export failed", str(exc))
            return
        QMessageBox.information(self, "Exported", f"Audit log written to {path}")

    def tick(self) -> None:
        pass

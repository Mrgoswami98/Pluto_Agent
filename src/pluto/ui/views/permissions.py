"""Permissions view — the permissions dashboard."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from pluto.core.application import PlutoApplication
from pluto.core.constants import ALWAYS_CONFIRM_ACTIONS
from pluto.core.logging_config import get_logger
from pluto.ui.theme import Palette
from pluto.ui.widgets.common import Card, PageHeader

log = get_logger("ui.permissions")


class PermissionsView(QWidget):
    """What Pluto is allowed to touch, and what it will always ask about."""

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
                "Permissions",
                "Nothing is granted by default. Pluto can only reach folders, "
                "websites and applications you add here.",
            )
        )

        tabs = QTabWidget()
        tabs.addTab(self._build_folders_tab(), "Folders")
        tabs.addTab(self._build_domains_tab(), "Websites")
        tabs.addTab(self._build_tools_tab(), "Tools")
        tabs.addTab(self._build_always_confirm_tab(), "Always confirm")
        layout.addWidget(tabs, stretch=1)

        self.refresh()

    # -- folders ----------------------------------------------------------
    def _build_folders_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(10)

        note = QLabel(
            "Pluto refuses any path outside these folders, including paths "
            "reached through shortcuts or '..' segments."
        )
        note.setObjectName("Muted")
        note.setWordWrap(True)
        layout.addWidget(note)

        self.folder_list = QListWidget()
        layout.addWidget(self.folder_list, stretch=1)

        buttons = QHBoxLayout()
        add_button = QPushButton("Add folder…")
        add_button.setObjectName("PrimaryButton")
        add_button.clicked.connect(self._add_folder)
        buttons.addWidget(add_button)

        add_ro_button = QPushButton("Add read-only folder…")
        add_ro_button.clicked.connect(lambda: self._add_folder(read_only=True))
        buttons.addWidget(add_ro_button)

        remove_button = QPushButton("Revoke selected")
        remove_button.clicked.connect(self._remove_folder)
        buttons.addWidget(remove_button)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        return page

    def _add_folder(self, read_only: bool = False) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Choose a folder for Pluto")
        if not folder:
            return
        try:
            self.app.add_folder(folder, read_only=read_only)
        except Exception as exc:
            QMessageBox.warning(
                self, "Cannot use that folder",
                getattr(exc, "user_message", None) or str(exc),
            )
            return
        self.refresh()

    def _remove_folder(self) -> None:
        item = self.folder_list.currentItem()
        if item is None:
            return
        path = item.data(Qt.ItemDataRole.UserRole)
        if path and self.app.remove_folder(path):
            self.refresh()

    # -- domains ----------------------------------------------------------
    def _build_domains_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(10)

        note = QLabel(
            "Pluto's browser can only open these sites. Subdomains are included; "
            "look-alike domains are not."
        )
        note.setObjectName("Muted")
        note.setWordWrap(True)
        layout.addWidget(note)

        self.domain_list = QListWidget()
        layout.addWidget(self.domain_list, stretch=1)

        entry = QHBoxLayout()
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("example.com")
        self.domain_input.returnPressed.connect(self._add_domain)
        entry.addWidget(self.domain_input, stretch=1)

        add_button = QPushButton("Approve site")
        add_button.setObjectName("PrimaryButton")
        add_button.clicked.connect(self._add_domain)
        entry.addWidget(add_button)

        remove_button = QPushButton("Revoke selected")
        remove_button.clicked.connect(self._remove_domain)
        entry.addWidget(remove_button)
        layout.addLayout(entry)
        return page

    def _add_domain(self) -> None:
        domain = self.domain_input.text().strip()
        if not domain:
            return
        self.app.add_domain(domain)
        self.domain_input.clear()
        self.refresh()

    def _remove_domain(self) -> None:
        item = self.domain_list.currentItem()
        if item is None:
            return
        if self.app.remove_domain(item.text()):
            self.refresh()

    # -- tools ------------------------------------------------------------
    def _build_tools_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(10)

        note = QLabel(
            "Turn individual tools off entirely. A disabled tool is refused "
            "before it runs and is not offered to the model."
        )
        note.setObjectName("Muted")
        note.setWordWrap(True)
        layout.addWidget(note)

        self.tool_table = QTableWidget()
        self.tool_table.setColumnCount(5)
        self.tool_table.setHorizontalHeaderLabels(
            ["Enabled", "Tool", "Risk", "Category", "What it does"]
        )
        self.tool_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.tool_table.verticalHeader().setVisible(False)
        self.tool_table.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.ResizeMode.Stretch
        )
        layout.addWidget(self.tool_table, stretch=1)
        return page

    def _build_always_confirm_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(10)

        card = Card()
        heading = QLabel("These always need your explicit confirmation")
        heading.setObjectName("SectionTitle")
        card.add(heading)

        explanation = QLabel(
            "This list cannot be turned off, and it applies in every autonomy "
            "mode including Supervised. A request phrased as 'just do it without "
            "asking' does not change it, and neither does a tool that declares "
            "itself low-risk."
        )
        explanation.setObjectName("Muted")
        explanation.setWordWrap(True)
        card.add(explanation)

        actions = QLabel(
            "\n".join(
                f"•  {action.replace('_', ' ')}"
                for action in sorted(ALWAYS_CONFIRM_ACTIONS)
            )
        )
        actions.setWordWrap(True)
        card.add(actions)
        layout.addWidget(card)
        layout.addStretch(1)
        return page

    # -- refresh ----------------------------------------------------------
    def refresh(self) -> None:
        self.folder_list.clear()
        described = self.app.path_guard.describe()
        for path in described["writable"]:
            item = QListWidgetItem(f"{path}    (read and write)")
            item.setData(Qt.ItemDataRole.UserRole, path)
            self.folder_list.addItem(item)
        for path in described["read_only"]:
            item = QListWidgetItem(f"{path}    (read only)")
            item.setData(Qt.ItemDataRole.UserRole, path)
            self.folder_list.addItem(item)
        if not described["writable"] and not described["read_only"]:
            self.folder_list.addItem(
                "No folders approved — Pluto cannot touch any files yet."
            )

        self.domain_list.clear()
        for domain in self.app.domain_policy.domains:
            self.domain_list.addItem(domain)
        if not self.app.domain_policy.domains:
            self.domain_list.addItem("No websites approved — browsing is disabled.")

        rows = self.app.registry.describe_all()
        self.tool_table.setRowCount(len(rows))
        for row, record in enumerate(rows):
            checkbox = QCheckBox()
            checkbox.setChecked(record["enabled"])
            checkbox.stateChanged.connect(
                lambda state, name=record["name"]: self._toggle_tool(name, bool(state))
            )
            if record["requires_windows"] and not record["enabled"]:
                checkbox.setEnabled(False)
                checkbox.setToolTip("Unavailable: this build is not running on Windows.")
            self.tool_table.setCellWidget(row, 0, checkbox)

            self.tool_table.setItem(row, 1, QTableWidgetItem(record["name"]))

            risk_item = QTableWidgetItem(record["risk_level"].replace("_", " "))
            risk_item.setToolTip(
                f"Risk level decides when Pluto must ask: {record['action_kind']}"
            )
            self.tool_table.setItem(row, 2, risk_item)

            self.tool_table.setItem(row, 3, QTableWidgetItem(record["category"]))
            self.tool_table.setItem(row, 4, QTableWidgetItem(record["description"]))

        self.tool_table.resizeColumnsToContents()
        self.tool_table.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.ResizeMode.Stretch
        )

    def _toggle_tool(self, name: str, enabled: bool) -> None:
        if enabled:
            self.app.permissions.enable_tool(name)
        else:
            self.app.permissions.disable_tool(name)
        disabled = [
            n for n in self.app.registry.names
            if not self.app.permissions.is_tool_enabled(n)
        ]
        self.app.preferences.set("disabled_tools", disabled)

    def tick(self) -> None:
        pass

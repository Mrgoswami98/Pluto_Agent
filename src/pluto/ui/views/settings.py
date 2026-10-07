"""Settings view — API key, model, budgets and diagnostics."""

from __future__ import annotations

import json

from PySide6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from pluto.core.application import PlutoApplication
from pluto.core.logging_config import get_logger
from pluto.security.secrets import mask_key
from pluto.ui.theme import Palette
from pluto.ui.widgets.common import Card, PageHeader, run_in_background

log = get_logger("ui.settings")

MODEL_CHOICES = [
    ("claude-sonnet-5-5", "Sonnet 5.5 — balanced speed and capability"),
    ("claude-opus-5-5", "Opus 5.5 — most capable, slower and costlier"),
    ("claude-haiku-4-5-20251001", "Haiku 4.5 — fastest and cheapest"),
]


class SettingsView(QWidget):
    """Configuration, with the API key handled through the OS credential store."""

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
                "Settings",
                "Your API key is stored in the Windows Credential Manager, not "
                "in a file and not in this application's settings.",
            )
        )

        tabs = QTabWidget()
        tabs.addTab(self._build_api_tab(), "API")
        tabs.addTab(self._build_limits_tab(), "Limits")
        tabs.addTab(self._build_diagnostics_tab(), "Diagnostics")
        layout.addWidget(tabs, stretch=1)

        self.refresh()

    # -- API --------------------------------------------------------------
    def _build_api_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(12)

        card = Card()
        form = QFormLayout()
        form.setSpacing(10)

        self.key_status = QLabel("")
        form.addRow("Current key:", self.key_status)

        self.key_input = QLineEdit()
        self.key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.key_input.setPlaceholderText("sk-ant-...")
        form.addRow("New key:", self.key_input)

        self.backend_label = QLabel("")
        self.backend_label.setObjectName("Muted")
        form.addRow("Stored in:", self.backend_label)

        self.model_box = QComboBox()
        for value, label in MODEL_CHOICES:
            self.model_box.addItem(label, value)
        form.addRow("Model:", self.model_box)

        card.body().addLayout(form)

        buttons = QHBoxLayout()
        self.save_key_button = QPushButton("Save key")
        self.save_key_button.setObjectName("PrimaryButton")
        self.save_key_button.clicked.connect(self._save_key)
        buttons.addWidget(self.save_key_button)

        self.test_button = QPushButton("Test connection")
        self.test_button.clicked.connect(self._test_connection)
        buttons.addWidget(self.test_button)

        self.remove_key_button = QPushButton("Remove key")
        self.remove_key_button.clicked.connect(self._remove_key)
        buttons.addWidget(self.remove_key_button)
        buttons.addStretch(1)
        card.body().addLayout(buttons)

        self.connection_label = QLabel("")
        self.connection_label.setWordWrap(True)
        card.add(self.connection_label)

        layout.addWidget(card)

        note = QLabel(
            "Get a key from console.anthropic.com. Pluto never asks you to put "
            "a key into a chat message, a file, or source code."
        )
        note.setObjectName("Muted")
        note.setWordWrap(True)
        layout.addWidget(note)
        layout.addStretch(1)
        return page

    def _save_key(self) -> None:
        key = self.key_input.text().strip()
        if not key:
            return
        if not key.startswith("sk-ant-"):
            answer = QMessageBox.question(
                self, "That does not look like a Claude key",
                "Anthropic keys usually start with 'sk-ant-'. Save it anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        try:
            backend = self.app.credentials.set(key)
        except Exception as exc:
            QMessageBox.warning(
                self, "Could not save the key",
                getattr(exc, "user_message", None) or str(exc),
            )
            return

        self.key_input.clear()
        self.app.claude.reset_connection()
        self.app.audit.log(
            "security", "api_key_set",
            summary=f"API key stored via {backend}",
        )
        self.refresh()
        self.connection_label.setText("Key saved. Use 'Test connection' to check it.")

    def _remove_key(self) -> None:
        answer = QMessageBox.question(
            self, "Remove the API key?",
            "Pluto will not be able to do anything until a new key is added.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.app.credentials.delete()
        self.app.claude.reset_connection()
        self.app.audit.log("security", "api_key_removed", summary="API key deleted")
        self.refresh()

    def _test_connection(self) -> None:
        self.test_button.setEnabled(False)
        self.connection_label.setText("Testing…")

        model = self.model_box.currentData()
        if model:
            self.app.claude.model = model

        def done(result: tuple[bool, str]) -> None:
            ok, message = result
            self.test_button.setEnabled(True)
            colour = (
                self.palette_colours.success if ok else self.palette_colours.danger
            )
            self.connection_label.setText(message)
            self.connection_label.setStyleSheet(f"color: {colour};")

        def failed(message: str, exc: Exception) -> None:
            self.test_button.setEnabled(True)
            self.connection_label.setText(message)
            self.connection_label.setStyleSheet(
                f"color: {self.palette_colours.danger};"
            )

        run_in_background(
            self.app.claude.test_connection, on_success=done, on_error=failed
        )

    # -- limits -----------------------------------------------------------
    def _build_limits_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(12)

        card = Card()
        heading = QLabel("Budgets and timeouts")
        heading.setObjectName("SectionTitle")
        card.add(heading)

        note = QLabel(
            "These are hard stops. A task that reaches one is halted and "
            "reported as partial, not quietly abandoned."
        )
        note.setObjectName("Muted")
        note.setWordWrap(True)
        card.add(note)

        form = QFormLayout()
        form.setSpacing(10)

        self.steps_spin = QSpinBox()
        self.steps_spin.setRange(1, 200)
        self.steps_spin.setValue(self.app.settings.max_steps_per_task)
        form.addRow("Max steps per task:", self.steps_spin)

        self.task_timeout_spin = QSpinBox()
        self.task_timeout_spin.setRange(10, 14_400)
        self.task_timeout_spin.setSuffix(" s")
        self.task_timeout_spin.setValue(self.app.settings.task_timeout_seconds)
        form.addRow("Task time limit:", self.task_timeout_spin)

        self.tool_timeout_spin = QSpinBox()
        self.tool_timeout_spin.setRange(1, 3_600)
        self.tool_timeout_spin.setSuffix(" s")
        self.tool_timeout_spin.setValue(self.app.settings.tool_timeout_seconds)
        form.addRow("Per-tool time limit:", self.tool_timeout_spin)

        self.retention_spin = QSpinBox()
        self.retention_spin.setRange(1, 3_650)
        self.retention_spin.setSuffix(" days")
        self.retention_spin.setValue(self.app.settings.retention_days)
        form.addRow("Keep history for:", self.retention_spin)

        card.body().addLayout(form)

        save_button = QPushButton("Save limits")
        save_button.setObjectName("PrimaryButton")
        save_button.clicked.connect(self._save_limits)
        card.add(save_button)

        layout.addWidget(card)

        privacy = Card()
        privacy_heading = QLabel("Privacy")
        privacy_heading.setObjectName("SectionTitle")
        privacy.add(privacy_heading)

        privacy_note = QLabel(
            "Pluto redacts API keys, tokens, passwords and card numbers before "
            "anything is written to the database or the logs. Deleting history "
            "below is immediate and cannot be undone."
        )
        privacy_note.setObjectName("Muted")
        privacy_note.setWordWrap(True)
        privacy.add(privacy_note)

        prune_button = QPushButton("Delete history older than the retention period")
        prune_button.clicked.connect(self._prune)
        privacy.add(prune_button)
        layout.addWidget(privacy)

        layout.addStretch(1)
        return page

    def _save_limits(self) -> None:
        self.app.preferences.set("max_steps_per_task", self.steps_spin.value())
        self.app.preferences.set("task_timeout_seconds", self.task_timeout_spin.value())
        self.app.preferences.set("tool_timeout_seconds", self.tool_timeout_spin.value())
        self.app.preferences.set("retention_days", self.retention_spin.value())

        self.app.orchestrator._max_steps = self.steps_spin.value()
        self.app.orchestrator._task_timeout = self.task_timeout_spin.value()

        QMessageBox.information(
            self, "Saved",
            "Limits updated. They apply to the next task you start.",
        )

    def _prune(self) -> None:
        days = self.retention_spin.value()
        answer = QMessageBox.question(
            self, "Delete old history?",
            f"Permanently delete tasks, audit entries and tool records older "
            f"than {days} days?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        tasks = self.app.tasks.prune_older_than(days)
        audit = self.app.audit.prune_older_than(days)
        tools = self.app.invocations.prune_older_than(days)
        QMessageBox.information(
            self, "Deleted",
            f"Removed {tasks} task(s), {audit} audit entries and "
            f"{tools} tool records.",
        )

    # -- diagnostics ------------------------------------------------------
    def _build_diagnostics_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(12)

        note = QLabel(
            "A snapshot of the running application. This contains no secrets "
            "and is safe to paste into a bug report."
        )
        note.setObjectName("Muted")
        note.setWordWrap(True)
        layout.addWidget(note)

        self.diagnostics = QPlainTextEdit()
        self.diagnostics.setReadOnly(True)
        layout.addWidget(self.diagnostics, stretch=1)

        buttons = QHBoxLayout()
        refresh_button = QPushButton("Refresh")
        refresh_button.clicked.connect(self._load_diagnostics)
        buttons.addWidget(refresh_button)

        copy_button = QPushButton("Copy to clipboard")
        copy_button.clicked.connect(self._copy_diagnostics)
        buttons.addWidget(copy_button)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        return page

    def _load_diagnostics(self) -> None:
        try:
            status = self.app.status()
        except Exception as exc:
            self.diagnostics.setPlainText(f"Could not read status: {exc}")
            return
        self.diagnostics.setPlainText(json.dumps(status, indent=2, default=str))

    def _copy_diagnostics(self) -> None:
        from PySide6.QtWidgets import QApplication

        QApplication.clipboard().setText(self.diagnostics.toPlainText())

    # -- refresh ----------------------------------------------------------
    def refresh(self) -> None:
        key = self.app.credentials.get()
        self.key_status.setText(mask_key(key))
        self.backend_label.setText(self.app.credentials.backend_name)

        current_model = self.app.claude.model
        for index in range(self.model_box.count()):
            if self.model_box.itemData(index) == current_model:
                self.model_box.setCurrentIndex(index)
                break

        self._load_diagnostics()

    def tick(self) -> None:
        pass

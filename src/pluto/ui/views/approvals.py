"""Approvals view — the approval centre."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from pluto.core.application import PlutoApplication
from pluto.core.logging_config import get_logger
from pluto.ui.theme import Palette
from pluto.ui.widgets.common import ApprovalCard, EmptyState, PageHeader

log = get_logger("ui.approvals")


class ApprovalsView(QWidget):
    """Every decision Pluto is waiting on."""

    def __init__(self, app: PlutoApplication, palette: Palette,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.app = app
        self.palette_colours = palette
        self._shown: set[str] = set()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        layout.addWidget(
            PageHeader(
                "Approvals",
                "Pluto stops here before anything consequential. Approvals are "
                "scoped to one action and expire, so an old approval cannot be "
                "reused for something else.",
            )
        )

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
            "Nothing waiting",
            "When Pluto needs permission for something — sending, deleting, "
            "buying, submitting — it will appear here.",
        )
        layout.addWidget(self.empty)

        self.refresh()

    def refresh(self) -> None:
        try:
            pending = self.app.approvals.list_pending()
        except Exception as exc:
            log.error("Could not load approvals: %s", exc)
            return

        self._clear()
        self.empty.setVisible(not pending)
        self.scroll.setVisible(bool(pending))

        for request in pending:
            card = ApprovalCard(request, self.palette_colours)
            card.approved.connect(self._approve)
            card.denied.connect(self._deny)
            self.list_layout.insertWidget(self.list_layout.count() - 1, card)
            self._shown.add(request.id)

    def tick(self) -> None:
        """Cheap check for new approvals while this view is visible."""
        try:
            current = {r.id for r in self.app.approvals.list_pending()}
        except Exception:
            return
        if current != self._shown:
            self.refresh()

    def _clear(self) -> None:
        self._shown.clear()
        while self.list_layout.count() > 1:
            item = self.list_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

    def _approve(self, approval_id: str) -> None:
        self.app.permissions.resolve_approval(approval_id, approved=True)
        self.refresh()

    def _deny(self, approval_id: str) -> None:
        self.app.permissions.resolve_approval(approval_id, approved=False)
        self.refresh()

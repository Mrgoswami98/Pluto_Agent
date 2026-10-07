"""Visual theme.

A single source of colour, spacing and typography so the interface is
consistent and both themes are legible. Contrast ratios for body text against
their backgrounds are kept at or above WCAG AA (4.5:1).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Palette:
    """Colours for one theme."""

    name: str
    # surfaces
    background: str
    surface: str
    surface_raised: str
    sidebar: str
    border: str
    # text
    text: str
    text_muted: str
    text_inverse: str
    # brand
    primary: str
    primary_hover: str
    primary_pressed: str
    # semantic
    success: str
    warning: str
    danger: str
    danger_hover: str
    info: str
    # risk levels, used consistently in badges and the approval centre
    risk_read_only: str
    risk_low: str
    risk_medium: str
    risk_high: str
    risk_critical: str


DARK = Palette(
    name="dark",
    background="#0f1419",
    surface="#171d26",
    surface_raised="#1e2630",
    sidebar="#0b0f14",
    border="#2a3542",
    text="#e8edf3",
    text_muted="#97a3b4",
    text_inverse="#0f1419",
    primary="#5b8def",
    primary_hover="#6f9bf2",
    primary_pressed="#4a7ad8",
    success="#3fb950",
    warning="#d29922",
    danger="#f85149",
    danger_hover="#ff6b63",
    info="#58a6ff",
    risk_read_only="#6e7781",
    risk_low="#3fb950",
    risk_medium="#d29922",
    risk_high="#f0883e",
    risk_critical="#f85149",
)

LIGHT = Palette(
    name="light",
    background="#f6f8fa",
    surface="#ffffff",
    surface_raised="#ffffff",
    sidebar="#eaeef2",
    border="#d0d7de",
    text="#1f2328",
    text_muted="#59636e",
    text_inverse="#ffffff",
    primary="#2563eb",
    primary_hover="#1d4ed8",
    primary_pressed="#1e40af",
    success="#1a7f37",
    warning="#9a6700",
    danger="#cf222e",
    danger_hover="#a40e26",
    info="#0969da",
    risk_read_only="#59636e",
    risk_low="#1a7f37",
    risk_medium="#9a6700",
    risk_high="#bc4c00",
    risk_critical="#cf222e",
)

#: Risk level value -> palette attribute.
RISK_COLOUR_ATTR = {
    "read_only": "risk_read_only",
    "low": "risk_low",
    "medium": "risk_medium",
    "high": "risk_high",
    "critical": "risk_critical",
}

#: Task status -> palette attribute, for status pills.
STATUS_COLOUR_ATTR = {
    "pending": "text_muted",
    "planning": "info",
    "awaiting_approval": "warning",
    "running": "primary",
    "verifying": "info",
    "completed": "success",
    "partial": "warning",
    "failed": "danger",
    "cancelled": "text_muted",
    "blocked": "text_muted",
}

FONT_STACK = '"Segoe UI", "Inter", system-ui, -apple-system, sans-serif'
MONO_STACK = '"Cascadia Code", "Consolas", "JetBrains Mono", monospace'


def risk_colour(palette: Palette, risk: str) -> str:
    return getattr(palette, RISK_COLOUR_ATTR.get(risk, "risk_low"))


def status_colour(palette: Palette, status: str) -> str:
    return getattr(palette, STATUS_COLOUR_ATTR.get(status, "text_muted"))


def build_stylesheet(palette: Palette) -> str:
    """Qt stylesheet for the whole application."""
    p = palette
    return f"""
* {{
    font-family: {FONT_STACK};
    font-size: 13px;
}}

QMainWindow, QDialog {{
    background-color: {p.background};
    color: {p.text};
}}

QWidget {{
    color: {p.text};
}}

/* ---- Sidebar ---- */
#Sidebar {{
    background-color: {p.sidebar};
    border-right: 1px solid {p.border};
}}

#SidebarButton {{
    background-color: transparent;
    border: none;
    border-radius: 8px;
    padding: 11px 14px;
    text-align: left;
    color: {p.text_muted};
    font-size: 13px;
}}
#SidebarButton:hover {{
    background-color: {p.surface_raised};
    color: {p.text};
}}
#SidebarButton:checked {{
    background-color: {p.primary};
    color: {p.text_inverse};
    font-weight: 600;
}}

#BrandName {{
    font-size: 16px;
    font-weight: 700;
    color: {p.text};
}}
#BrandTagline {{
    font-size: 11px;
    color: {p.text_muted};
}}

/* ---- Cards and panels ---- */
#Card {{
    background-color: {p.surface};
    border: 1px solid {p.border};
    border-radius: 10px;
}}

#PageTitle {{
    font-size: 20px;
    font-weight: 700;
    color: {p.text};
}}
#PageSubtitle {{
    font-size: 12px;
    color: {p.text_muted};
}}
#SectionTitle {{
    font-size: 14px;
    font-weight: 600;
    color: {p.text};
}}
#Muted {{
    color: {p.text_muted};
}}

/* ---- Buttons ---- */
QPushButton {{
    background-color: {p.surface_raised};
    color: {p.text};
    border: 1px solid {p.border};
    border-radius: 7px;
    padding: 8px 15px;
    font-weight: 500;
}}
QPushButton:hover {{
    border-color: {p.primary};
}}
QPushButton:disabled {{
    color: {p.text_muted};
    background-color: {p.surface};
}}

#PrimaryButton {{
    background-color: {p.primary};
    color: {p.text_inverse};
    border: none;
    font-weight: 600;
}}
#PrimaryButton:hover {{ background-color: {p.primary_hover}; }}
#PrimaryButton:pressed {{ background-color: {p.primary_pressed}; }}
#PrimaryButton:disabled {{
    background-color: {p.border};
    color: {p.text_muted};
}}

#DangerButton {{
    background-color: {p.danger};
    color: #ffffff;
    border: none;
    font-weight: 700;
}}
#DangerButton:hover {{ background-color: {p.danger_hover}; }}

#EmergencyStop {{
    background-color: {p.danger};
    color: #ffffff;
    border: none;
    border-radius: 8px;
    padding: 11px 16px;
    font-weight: 700;
    font-size: 13px;
}}
#EmergencyStop:hover {{ background-color: {p.danger_hover}; }}
#EmergencyStop:checked {{
    background-color: {p.warning};
    color: {p.text_inverse};
}}

#ApproveButton {{
    background-color: {p.success};
    color: #ffffff;
    border: none;
    font-weight: 600;
}}

/* ---- Inputs ---- */
QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QSpinBox {{
    background-color: {p.surface_raised};
    color: {p.text};
    border: 1px solid {p.border};
    border-radius: 7px;
    padding: 8px 11px;
    selection-background-color: {p.primary};
    selection-color: {p.text_inverse};
}}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QComboBox:focus {{
    border-color: {p.primary};
}}
QLineEdit::placeholder {{ color: {p.text_muted}; }}

QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox QAbstractItemView {{
    background-color: {p.surface_raised};
    color: {p.text};
    border: 1px solid {p.border};
    selection-background-color: {p.primary};
    selection-color: {p.text_inverse};
}}

QCheckBox, QRadioButton {{ spacing: 8px; color: {p.text}; }}
QCheckBox::indicator, QRadioButton::indicator {{
    width: 17px; height: 17px;
    border: 1px solid {p.border};
    border-radius: 4px;
    background-color: {p.surface_raised};
}}
QCheckBox::indicator:checked, QRadioButton::indicator:checked {{
    background-color: {p.primary};
    border-color: {p.primary};
}}

/* ---- Lists and tables ---- */
QListWidget, QTreeWidget, QTableWidget {{
    background-color: {p.surface};
    color: {p.text};
    border: 1px solid {p.border};
    border-radius: 8px;
    outline: none;
}}
QListWidget::item, QTreeWidget::item {{
    padding: 7px 9px;
    border-radius: 6px;
}}
QListWidget::item:selected, QTreeWidget::item:selected,
QTableWidget::item:selected {{
    background-color: {p.primary};
    color: {p.text_inverse};
}}
QHeaderView::section {{
    background-color: {p.surface_raised};
    color: {p.text_muted};
    border: none;
    border-bottom: 1px solid {p.border};
    padding: 8px;
    font-weight: 600;
}}

/* ---- Progress ---- */
QProgressBar {{
    background-color: {p.surface_raised};
    border: none;
    border-radius: 5px;
    height: 7px;
    text-align: center;
    color: transparent;
}}
QProgressBar::chunk {{
    background-color: {p.primary};
    border-radius: 5px;
}}

/* ---- Tabs ---- */
QTabWidget::pane {{
    border: 1px solid {p.border};
    border-radius: 8px;
    background-color: {p.surface};
}}
QTabBar::tab {{
    background-color: transparent;
    color: {p.text_muted};
    padding: 9px 17px;
    border: none;
    margin-right: 3px;
}}
QTabBar::tab:selected {{
    color: {p.text};
    border-bottom: 2px solid {p.primary};
    font-weight: 600;
}}

/* ---- Scrollbars ---- */
QScrollBar:vertical {{
    background: transparent; width: 11px; margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {p.border}; border-radius: 5px; min-height: 28px;
}}
QScrollBar::handle:vertical:hover {{ background: {p.text_muted}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QScrollBar:horizontal {{ background: transparent; height: 11px; }}
QScrollBar::handle:horizontal {{
    background: {p.border}; border-radius: 5px; min-width: 28px;
}}

/* ---- Misc ---- */
QSplitter::handle {{ background-color: {p.border}; }}
QStatusBar {{ background-color: {p.sidebar}; color: {p.text_muted}; }}
QToolTip {{
    background-color: {p.surface_raised};
    color: {p.text};
    border: 1px solid {p.border};
    border-radius: 6px;
    padding: 6px 9px;
}}
QGroupBox {{
    border: 1px solid {p.border};
    border-radius: 8px;
    margin-top: 14px;
    padding-top: 14px;
    font-weight: 600;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 11px;
    padding: 0 6px;
    color: {p.text_muted};
}}
"""


def resolve_palette(theme: str) -> Palette:
    """Map the theme setting to a palette, following the OS for 'system'."""
    if theme == "light":
        return LIGHT
    if theme == "dark":
        return DARK
    return _detect_system_palette()


def _detect_system_palette() -> Palette:
    """Best-effort OS theme detection; dark is the fallback."""
    try:
        import sys

        if sys.platform == "win32":
            import winreg

            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
            )
            value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
            return LIGHT if value == 1 else DARK
    except Exception:
        pass

    try:
        from PySide6.QtWidgets import QApplication

        app = QApplication.instance()
        if app is not None:
            window = app.palette().window().color()
            # Perceived luminance; above half means a light desktop theme.
            luminance = (
                0.299 * window.red() + 0.587 * window.green() + 0.114 * window.blue()
            ) / 255
            return LIGHT if luminance > 0.5 else DARK
    except Exception:
        pass

    return DARK

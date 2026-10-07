# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for Pluto Advance 0.5.

Build (on Windows):
    pyinstaller packaging/windows/pluto.spec --clean --noconfirm

Produces packaging/windows/dist/PlutoAdvance/PlutoAdvance.exe

A one-folder build is used rather than --onefile: start-up is noticeably
faster, and antivirus heuristics are far less hostile to it, which matters for
an unsigned application.
"""

from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

SPEC_DIR = Path(SPECPATH).resolve()
PROJECT_ROOT = SPEC_DIR.parent.parent
SRC = PROJECT_ROOT / "src"

# Modules PyInstaller's static analysis misses because they are imported
# lazily or by name.
hidden_imports = [
    "pluto.ui.views.chat",
    "pluto.ui.views.tasks",
    "pluto.ui.views.approvals",
    "pluto.ui.views.activity",
    "pluto.ui.views.permissions",
    "pluto.ui.views.memory",
    "pluto.ui.views.settings",
    "pluto.tools.files",
    "pluto.tools.spreadsheet",
    "pluto.automation.browser",
    "pluto.automation.windows",
    # keyring resolves its backend at runtime by entry point.
    "keyring.backends.Windows",
    "keyring.backends.chainer",
    "keyring.backends.fail",
    "win32timezone",
    # openpyxl writer modules are imported dynamically by pandas.
    "openpyxl.cell._writer",
]
hidden_imports += collect_submodules("anthropic")

datas = []
datas += collect_data_files("anthropic")
datas += collect_data_files("certifi")

icon_path = PROJECT_ROOT / "assets" / "pluto.ico"
version_path = SPEC_DIR / "version_info.txt"

a = Analysis(
    [str(SRC / "pluto" / "__main__.py")],
    pathex=[str(SRC)],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # Playwright drives a browser out of process and is resolved at runtime;
    # bundling it bloats the build without helping.
    excludes=[
        "tkinter", "matplotlib", "scipy", "notebook", "IPython",
        "pytest", "_pytest", "mypy", "ruff",
    ],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="PlutoAdvance",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,          # UPX compression trips antivirus heuristics
    console=False,      # GUI application: no console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(icon_path) if icon_path.exists() else None,
    version=str(version_path) if version_path.exists() else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="PlutoAdvance",
)

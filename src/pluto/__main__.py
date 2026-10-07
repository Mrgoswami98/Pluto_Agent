"""Entry point for Pluto Advance 0.5.

``python -m pluto`` or the ``pluto`` console script. Starts the desktop
interface; ``--check`` runs a non-GUI health check, which is what the installer
and CI use to confirm a build actually works.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import NoReturn

from pluto import __version__


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="pluto",
        description="Pluto Advance 0.5 — Your Intelligent Digital Operator",
    )
    parser.add_argument("--version", action="version", version=f"Pluto Advance {__version__}")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Run a health check and exit. No window is opened.",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Print the application status as JSON and exit.",
    )
    parser.add_argument(
        "--data-dir",
        help="Override where Pluto keeps its database and logs.",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Override the log level.",
    )
    return parser.parse_args(argv)


def _build_app(args: argparse.Namespace):
    from pluto.core.config import get_settings

    overrides: dict[str, object] = {}
    if args.data_dir:
        overrides["data_dir"] = args.data_dir
    if args.log_level:
        overrides["log_level"] = args.log_level

    settings = get_settings().with_overrides(**overrides) if overrides else get_settings()

    from pluto.core.application import PlutoApplication, restore_preferences

    app = PlutoApplication(settings)
    restore_preferences(app)
    return app


def run_check(args: argparse.Namespace) -> int:
    """Start the application without a window and report what works.

    Used by CI and after installation. Exit code 0 means the core starts; a
    missing API key is reported but is not a failure, because configuring it is
    a first-run step rather than a broken build.
    """
    print(f"Pluto Advance {__version__} — health check")
    print(f"Python {sys.version.split()[0]} on {sys.platform}\n")

    try:
        app = _build_app(args)
    except Exception as exc:
        print(f"FAILED: the application could not start: {exc}")
        return 1

    try:
        status = app.status()
        checks = [
            ("Database", status["schema_version"] > 0,
             f"schema v{status['schema_version']} at {status['database']}"),
            ("Tools registered", status["tools_registered"] > 0,
             f"{status['tools_enabled']} of {status['tools_registered']} enabled"),
            ("Credential storage", True, status["credential_backend"]),
            ("API key", status["api_key_configured"],
             "configured" if status["api_key_configured"]
             else "not set — add one in Settings on first run"),
            ("Windows automation", status["is_windows"],
             "available" if status["is_windows"]
             else f"unavailable on {status['platform']} (expected off Windows)"),
        ]

        failures = 0
        for name, ok, detail in checks:
            # A missing key or non-Windows platform is informational, not fatal.
            fatal = name in {"Database", "Tools registered"}
            if ok:
                mark = "PASS"
            elif fatal:
                mark = "FAIL"
                failures += 1
            else:
                mark = "INFO"
            print(f"  [{mark}] {name}: {detail}")

        print()
        if failures:
            print(f"{failures} check(s) failed.")
            return 1
        print("Core application starts correctly.")
        return 0
    finally:
        app.shutdown()


def run_status(args: argparse.Namespace) -> int:
    app = _build_app(args)
    try:
        print(json.dumps(app.status(), indent=2, default=str))
        return 0
    finally:
        app.shutdown()


def run_gui(args: argparse.Namespace) -> int:
    """Start the desktop interface."""
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError:
        print(
            "PySide6 is not installed, so the desktop interface cannot start.\n"
            "Install it with:  pip install PySide6\n"
            "Or run 'pluto --check' to verify the core without a window.",
            file=sys.stderr,
        )
        return 2

    from pluto.core.logging_config import get_logger

    log = get_logger("main")

    qt_app = QApplication(sys.argv)
    qt_app.setApplicationName("Pluto Advance")
    qt_app.setApplicationVersion(__version__)
    qt_app.setOrganizationName("Pluto Advance")

    try:
        app = _build_app(args)
    except Exception as exc:
        from PySide6.QtWidgets import QMessageBox

        QMessageBox.critical(
            None,
            "Pluto could not start",
            f"{getattr(exc, 'user_message', None) or exc}\n\n"
            f"If this keeps happening, check the logs in your "
            f"PlutoAdvance data folder.",
        )
        return 1

    from pluto.ui.main_window import MainWindow

    window = MainWindow(app)
    window.show()
    log.info("Pluto Advance %s window shown", __version__)

    return qt_app.exec()


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.check:
        return run_check(args)
    if args.status:
        return run_status(args)
    return run_gui(args)


def _entry() -> NoReturn:  # pragma: no cover - console script shim
    sys.exit(main())


if __name__ == "__main__":
    sys.exit(main())

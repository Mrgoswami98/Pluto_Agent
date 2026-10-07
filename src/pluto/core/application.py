"""Application wiring.

:class:`PlutoApplication` builds the object graph once and hands it to the UI.
Keeping construction here means the GUI, the CLI and the test suite all get an
identically-wired application, and the dependency order stays visible in one
readable place.
"""

from __future__ import annotations

import sys
import threading
from typing import Any

from pluto.agent.orchestrator import ExecutionEvents, TaskOrchestrator
from pluto.ai.client import ClaudeClient
from pluto.ai.planner import Planner
from pluto.ai.prompts import build_system_prompt
from pluto.automation.browser import BrowserSession, DomainPolicy, build_browser_tools
from pluto.automation.windows import (
    IS_WINDOWS,
    ApplicationPolicy,
    build_windows_tools,
)
from pluto.core.config import Settings, get_settings
from pluto.core.constants import AutonomyMode
from pluto.core.logging_config import configure_logging, get_logger
from pluto.data.database import Database
from pluto.data.repositories import (
    ApprovalRepository,
    AuditRepository,
    MemoryRepository,
    PreferenceRepository,
    ScheduleRepository,
    TaskRepository,
    ToolInvocationRepository,
)
from pluto.security.paths import PathGuard
from pluto.security.permissions import EmergencyStop, PermissionEngine
from pluto.security.secrets import CredentialStore
from pluto.tools.files import build_file_tools
from pluto.tools.registry import ToolRegistry
from pluto.tools.spreadsheet import build_spreadsheet_tools

log = get_logger("core.application")


class PlutoApplication:
    """The assembled application, independent of any user interface."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.settings.ensure_directories()

        configure_logging(
            log_dir=self.settings.log_dir,
            level=self.settings.log_level,
            max_bytes=self.settings.log_max_bytes,
            backup_count=self.settings.log_backup_count,
            console=True,
            force=True,
        )
        log.info("Starting Pluto Advance on %s", sys.platform)

        # -- storage ------------------------------------------------------
        self.database = Database(self.settings.database_path)
        self.database.initialise()

        self.tasks = TaskRepository(self.database)
        self.approvals = ApprovalRepository(self.database)
        self.audit = AuditRepository(self.database)
        self.invocations = ToolInvocationRepository(self.database)
        self.memory = MemoryRepository(self.database)
        self.preferences = PreferenceRepository(self.database)
        self.schedules = ScheduleRepository(self.database)

        # -- security -----------------------------------------------------
        self.credentials = CredentialStore(
            fallback_path=self.settings.credential_fallback_path,
            allow_file_fallback=self.settings.allow_file_credential_fallback,
        )
        self.emergency_stop = EmergencyStop()
        self.path_guard = PathGuard(
            allowed_roots=self.settings.allowed_folders,
            read_only_roots=self.settings.read_only_folders,
        )
        self.permissions = PermissionEngine(
            autonomy_mode=self.settings.autonomy_mode,
            approval_repo=self.approvals,
            audit_repo=self.audit,
            emergency_stop=self.emergency_stop,
        )

        # -- automation ---------------------------------------------------
        self.domain_policy = DomainPolicy(self.settings.allowed_domains)
        self.browser = BrowserSession(
            self.domain_policy,
            headless=self.settings.browser_headless,
            timeout_seconds=self.settings.browser_timeout_seconds,
        )
        self.application_policy = ApplicationPolicy(self.settings.allowed_applications)

        # -- tools --------------------------------------------------------
        self.registry = ToolRegistry(
            self.permissions,
            audit_repo=self.audit,
            invocation_repo=self.invocations,
            default_timeout=self.settings.tool_timeout_seconds,
        )
        self._register_tools()

        # -- intelligence -------------------------------------------------
        self.claude = ClaudeClient(
            credential_store=self.credentials,
            model=self.settings.model,
            max_tokens=self.settings.max_tokens,
            temperature=self.settings.temperature,
            timeout=self.settings.api_timeout_seconds,
            max_retries=self.settings.api_max_retries,
        )
        self.planner = Planner(
            self.claude, self.registry, max_steps=self.settings.max_steps_per_task
        )
        self.events = ExecutionEvents()
        self.orchestrator = TaskOrchestrator(
            self.registry,
            self.permissions,
            task_repo=self.tasks,
            audit_repo=self.audit,
            events=self.events,
            max_steps=self.settings.max_steps_per_task,
            task_timeout_seconds=self.settings.task_timeout_seconds,
        )

        self._lock = threading.RLock()
        self.audit.log(
            "application", "started",
            summary=f"Pluto Advance started on {sys.platform}",
            details={"windows": IS_WINDOWS, "tools": len(self.registry.names)},
        )

    # -- tools ------------------------------------------------------------
    def _register_tools(self) -> None:
        self.registry.register_all(build_file_tools(self.path_guard))
        self.registry.register_all(build_spreadsheet_tools(self.path_guard))
        self.registry.register_all(build_browser_tools(self.browser))
        self.registry.register_all(
            build_windows_tools(
                self.application_policy,
                self.path_guard,
                screenshots_enabled=self.settings.screenshot_enabled,
            )
        )
        if not IS_WINDOWS:
            # Visible in the dashboard, but not offered to the model, so it does
            # not plan steps that are certain to fail.
            for tool in self.registry.list_tools():
                if tool.requires_windows:
                    self.permissions.disable_tool(tool.name)
            log.info("Windows automation tools disabled: not running on Windows")

    # -- state ------------------------------------------------------------
    @property
    def is_configured(self) -> bool:
        """True when Pluto has what it needs to do real work."""
        return self.claude.has_api_key

    def system_prompt(self) -> str:
        return build_system_prompt(
            autonomy_mode=self.permissions.autonomy_mode,
            allowed_folders=[str(p) for p in self.path_guard.allowed_roots],
            allowed_domains=self.domain_policy.domains,
            tool_names=[
                name for name in self.registry.names
                if self.permissions.is_tool_enabled(name)
            ],
            platform_note=(
                None
                if IS_WINDOWS
                else (
                    f"Note: this build is running on {sys.platform}, not Windows, "
                    f"so desktop automation tools are unavailable. Say so if the "
                    f"user asks for them."
                )
            ),
        )

    def set_autonomy_mode(self, mode: AutonomyMode) -> None:
        self.permissions.set_autonomy_mode(mode)
        self.preferences.set("autonomy_mode", mode.value)

    def add_folder(self, folder: str, *, read_only: bool = False) -> str:
        path = self.path_guard.add_root(folder, read_only=read_only)
        self.preferences.set(
            "allowed_folders", [str(p) for p in self.path_guard.allowed_roots]
        )
        self.audit.log(
            "security", "folder_granted",
            summary=f"Granted {'read-only' if read_only else 'write'} access to {path}",
        )
        return str(path)

    def remove_folder(self, folder: str) -> bool:
        removed = self.path_guard.remove_root(folder)
        if removed:
            self.preferences.set(
                "allowed_folders", [str(p) for p in self.path_guard.allowed_roots]
            )
            self.audit.log("security", "folder_revoked", summary=f"Revoked {folder}")
        return removed

    def add_domain(self, domain: str) -> None:
        self.domain_policy.allow(domain)
        self.preferences.set("allowed_domains", self.domain_policy.domains)
        self.audit.log("security", "domain_granted", summary=f"Approved {domain}")

    def remove_domain(self, domain: str) -> bool:
        removed = self.domain_policy.revoke(domain)
        if removed:
            self.preferences.set("allowed_domains", self.domain_policy.domains)
            self.audit.log("security", "domain_revoked", summary=f"Revoked {domain}")
        return removed

    def engage_emergency_stop(self, reason: str = "Emergency Stop pressed") -> int:
        """Stop everything. Returns how many running tasks were signalled."""
        self.emergency_stop.engage(reason)
        cancelled = self.orchestrator.cancel_all(reason=reason)
        pending = 0
        for task in self.tasks.list_active():
            pending += self.approvals.cancel_pending_for_task(task.id)
        self.audit.log(
            "security", "emergency_stop",
            outcome="engaged",
            summary=f"{reason}; signalled {cancelled} running task(s)",
            details={"running_signalled": cancelled, "approvals_cancelled": pending},
        )
        return cancelled

    def reset_emergency_stop(self) -> None:
        self.emergency_stop.reset()
        self.audit.log("security", "emergency_stop", outcome="reset",
                       summary="Emergency Stop reset")

    def status(self) -> dict[str, Any]:
        """Snapshot for the dashboard and diagnostics."""
        return {
            "version": __import__("pluto").__version__,
            "platform": sys.platform,
            "is_windows": IS_WINDOWS,
            "api_key_configured": self.claude.has_api_key,
            "credential_backend": self.credentials.backend_name,
            "model": self.claude.model,
            "autonomy_mode": self.permissions.autonomy_mode.value,
            "emergency_stop": self.emergency_stop.engaged,
            "tools_registered": len(self.registry.names),
            "tools_enabled": sum(
                1 for n in self.registry.names if self.permissions.is_tool_enabled(n)
            ),
            "allowed_folders": [str(p) for p in self.path_guard.allowed_roots],
            "allowed_domains": self.domain_policy.domains,
            "database": str(self.settings.database_path),
            "database_size_bytes": self.database.size_bytes(),
            "schema_version": self.database.schema_version,
            "pending_approvals": len(self.approvals.list_pending()),
            "active_tasks": len(self.tasks.list_active()),
            "token_usage": self.claude.usage.snapshot(),
        }

    def shutdown(self) -> None:
        """Release everything. Safe to call more than once."""
        log.info("Shutting down Pluto Advance")
        try:
            self.audit.log("application", "stopped", summary="Pluto Advance shut down")
        except Exception:
            pass
        self.orchestrator.cancel_all(reason="Application shutting down")
        self.registry.shutdown()
        self.browser.shutdown()
        self.database.close()


def restore_preferences(app: PlutoApplication) -> None:
    """Re-apply settings the user saved in a previous session."""
    mode = app.preferences.get("autonomy_mode")
    if mode:
        try:
            app.permissions.set_autonomy_mode(AutonomyMode(mode))
        except ValueError:
            log.warning("Ignoring unknown saved autonomy mode: %s", mode)

    for folder in app.preferences.get("allowed_folders", []) or []:
        try:
            app.path_guard.add_root(folder)
        except Exception as exc:
            log.warning("Could not restore folder %s: %s", folder, exc)

    for domain in app.preferences.get("allowed_domains", []) or []:
        app.domain_policy.allow(domain)

    for name in app.preferences.get("disabled_tools", []) or []:
        app.permissions.disable_tool(name)

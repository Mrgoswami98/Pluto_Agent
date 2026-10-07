"""Exception hierarchy for Pluto Advance.

Every failure mode the agent can hit has a named exception so that callers can
react precisely instead of catching bare ``Exception``. Exceptions carry a
``user_message`` that is safe to show in the UI (no secrets, no raw paths of
other users' data) and an optional ``detail`` for the audit log.
"""

from __future__ import annotations


class PlutoError(Exception):
    """Base class for every error raised by Pluto."""

    #: Shown to the user when nothing more specific is supplied.
    default_user_message = "Something went wrong."

    def __init__(
        self,
        message: str,
        *,
        user_message: str | None = None,
        detail: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.user_message = user_message or self.default_user_message
        self.detail = detail

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.message


# --------------------------------------------------------------------------
# Configuration & startup
# --------------------------------------------------------------------------
class ConfigurationError(PlutoError):
    """Settings are missing or invalid."""

    default_user_message = "Pluto is not configured correctly. Open Settings to fix it."


class MissingAPIKeyError(ConfigurationError):
    """No Claude API key is available from any source."""

    default_user_message = (
        "No Claude API key found. Add one in Settings — Pluto cannot think without it."
    )


# --------------------------------------------------------------------------
# Security & permissions
# --------------------------------------------------------------------------
class SecurityError(PlutoError):
    """Base class for refusals made on security grounds."""

    default_user_message = "Pluto refused that action for safety reasons."


class PermissionDeniedError(SecurityError):
    """The permission engine refused the action."""

    default_user_message = "That action is not permitted under the current settings."


class ApprovalRequiredError(SecurityError):
    """The action needs explicit human approval that was not granted."""

    default_user_message = "That action needs your approval before Pluto can run it."


class ApprovalDeniedError(SecurityError):
    """A human was asked and said no."""

    default_user_message = "You declined that action, so Pluto stopped."


class PathTraversalError(SecurityError):
    """A path escaped the configured sandbox."""

    default_user_message = "That location is outside the folders Pluto is allowed to use."


class UnsafeContentError(SecurityError):
    """Untrusted content tried to act as an instruction."""

    default_user_message = (
        "Pluto found instruction-like text inside untrusted content and ignored it."
    )


# --------------------------------------------------------------------------
# Tools
# --------------------------------------------------------------------------
class ToolError(PlutoError):
    """Base class for tool failures."""

    default_user_message = "A tool failed to complete."


class ToolNotFoundError(ToolError):
    """No tool is registered under the requested name."""

    default_user_message = "Pluto tried to use a tool that does not exist."


class ToolValidationError(ToolError):
    """Tool arguments failed schema validation."""

    default_user_message = "The tool was called with invalid arguments."


class ToolTimeoutError(ToolError):
    """A tool exceeded its time budget."""

    default_user_message = "A tool took too long and was stopped."


class ToolExecutionError(ToolError):
    """A tool ran but failed."""

    default_user_message = "A tool ran into an error."


class VerificationError(ToolError):
    """The action ran but the result could not be verified."""

    default_user_message = (
        "Pluto could not confirm the action actually worked, so it was not marked done."
    )


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------
class OrchestrationError(PlutoError):
    """Base class for planner/executor failures."""

    default_user_message = "Pluto could not carry out the plan."


class PlanningError(OrchestrationError):
    """The model failed to produce a usable plan."""

    default_user_message = "Pluto could not turn that request into a workable plan."


class TaskCancelledError(OrchestrationError):
    """The task was cancelled by the user or emergency stop."""

    default_user_message = "The task was cancelled."


class EmergencyStopError(TaskCancelledError):
    """Emergency stop was engaged."""

    default_user_message = "Emergency Stop was pressed. Pluto halted all work."


class BudgetExceededError(OrchestrationError):
    """A step, token or time budget was exhausted."""

    default_user_message = "The task hit its configured limit and was stopped."


class RetryLimitExceededError(OrchestrationError):
    """Too many retries."""

    default_user_message = "Pluto retried as far as it is allowed and still failed."


# --------------------------------------------------------------------------
# External providers
# --------------------------------------------------------------------------
class ProviderError(PlutoError):
    """Base class for failures from an external service."""

    default_user_message = "An external service failed."


class ModelAPIError(ProviderError):
    """The Claude API returned an error."""

    default_user_message = "The Claude API returned an error."


class RateLimitError(ModelAPIError):
    """The Claude API rate-limited us."""

    default_user_message = "Claude is rate-limiting requests. Pluto will back off and retry."


class BrowserAutomationError(ProviderError):
    """Playwright failed."""

    default_user_message = "The browser automation step failed."


class WindowsAutomationError(ProviderError):
    """Windows UI Automation failed."""

    default_user_message = "The Windows automation step failed."


class UnsupportedPlatformError(PlutoError):
    """A Windows-only capability was requested on another OS."""

    default_user_message = "That feature only works on Windows."


# --------------------------------------------------------------------------
# Storage
# --------------------------------------------------------------------------
class StorageError(PlutoError):
    """Database or filesystem persistence failed."""

    default_user_message = "Pluto could not save its data."


class MigrationError(StorageError):
    """Schema migration failed."""

    default_user_message = "The local database could not be upgraded."

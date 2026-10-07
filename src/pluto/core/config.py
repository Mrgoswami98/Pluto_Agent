"""Application configuration.

Settings resolve in this order, later winning:

1. Built-in defaults (safe: no folders granted, no domains allowed).
2. ``.env`` file, if present.
3. Environment variables prefixed ``PLUTO_``.
4. Values saved in the app database by the Settings screen.

The API key is deliberately *not* part of this model — it lives in
:class:`~pluto.security.secrets.CredentialStore` so it never lands in a config
dump, a log line or a crash report.
"""

from __future__ import annotations

import os
import sys
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field, computed_field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from pluto.core.constants import (
    DEFAULT_MAX_STEPS,
    DEFAULT_TASK_TIMEOUT,
    DEFAULT_TOOL_TIMEOUT,
    AutonomyMode,
)

APP_DIR_NAME = "PlutoAdvance"
ORG_NAME = "PlutoAdvance"


def default_data_dir() -> Path:
    """Per-user writable location for database, logs and evidence.

    Deliberately outside the installation directory so that an installed copy
    under ``C:\\Program Files`` never needs write access to itself.
    """
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local")
        return Path(base) / APP_DIR_NAME
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_DIR_NAME
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "pluto-advance"


def _split_paths(raw: str) -> list[str]:
    """Split a path list into components.

    A semicolon always wins when present, because a Windows path list
    (``C:\\One;C:\\Two``) contains colons that are *not* separators. Only when
    there is no semicolon do we fall back to the platform separator.
    """
    if not raw:
        return []
    sep = ";" if ";" in raw else os.pathsep
    parts = raw.split(sep)
    return [p.strip().strip('"') for p in parts if p.strip()]


class Settings(BaseSettings):
    """Runtime configuration for Pluto Advance."""

    model_config = SettingsConfigDict(
        env_prefix="PLUTO_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
        validate_assignment=True,
    )

    # -- model ------------------------------------------------------------
    model: str = Field(
        default="claude-sonnet-5-5",
        description="Claude model used for planning, chat and verification.",
    )
    max_tokens: int = Field(default=4096, ge=256, le=64_000)
    temperature: float = Field(default=0.2, ge=0.0, le=1.0)
    api_timeout_seconds: float = Field(default=120.0, gt=0, le=600)
    api_max_retries: int = Field(default=3, ge=0, le=8)

    # -- storage ----------------------------------------------------------
    data_dir: Path = Field(default_factory=default_data_dir)

    # -- autonomy & budgets ----------------------------------------------
    autonomy_mode: AutonomyMode = Field(default=AutonomyMode.ASSISTED)
    max_steps_per_task: int = Field(default=DEFAULT_MAX_STEPS, ge=1, le=200)
    task_timeout_seconds: int = Field(default=DEFAULT_TASK_TIMEOUT, ge=10, le=14_400)
    tool_timeout_seconds: int = Field(default=DEFAULT_TOOL_TIMEOUT, ge=1, le=3_600)
    max_retries_per_step: int = Field(default=2, ge=0, le=5)
    max_concurrent_steps: int = Field(default=3, ge=1, le=10)
    token_budget_per_task: int = Field(default=200_000, ge=1_000)

    # -- filesystem sandbox ----------------------------------------------
    # NoDecode stops pydantic-settings trying to JSON-parse the env value, so
    # our own separator-aware validator below sees the raw string.
    allowed_folders: Annotated[list[Path], NoDecode] = Field(default_factory=list)
    read_only_folders: Annotated[list[Path], NoDecode] = Field(default_factory=list)

    # -- browser ----------------------------------------------------------
    browser_headless: bool = Field(
        default=False,
        description="Keep False. Hidden automation is against the product's policy.",
    )
    allowed_domains: Annotated[list[str], NoDecode] = Field(default_factory=list)
    browser_timeout_seconds: int = Field(default=45, ge=5, le=600)
    browser_reuse_session: bool = Field(default=False)

    # -- windows automation ----------------------------------------------
    windows_automation_enabled: bool = Field(default=False)
    allowed_applications: Annotated[list[str], NoDecode] = Field(default_factory=list)
    screenshot_enabled: bool = Field(default=False)

    # -- logging & retention ---------------------------------------------
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_max_bytes: int = Field(default=5 * 1024 * 1024, ge=64 * 1024)
    log_backup_count: int = Field(default=5, ge=0, le=50)
    retention_days: int = Field(default=90, ge=1, le=3_650)
    store_evidence: bool = Field(default=True)

    # -- memory -----------------------------------------------------------
    memory_enabled: bool = Field(default=True)
    episodic_memory_limit: int = Field(default=500, ge=0)
    memory_exclude_sensitive: bool = Field(default=True)

    # -- voice ------------------------------------------------------------
    speech_provider: Literal["none", "openai", "azure", "google"] = "none"
    speech_language: str = Field(default="auto")
    voice_output_enabled: bool = Field(default=False)

    # -- ui ---------------------------------------------------------------
    theme: Literal["system", "light", "dark"] = "system"
    ui_language: Literal["auto", "en", "hi"] = "auto"

    # -- developer --------------------------------------------------------
    allow_file_credential_fallback: bool = Field(
        default=False,
        description="Development only. Lets the API key live in a 0600 file.",
    )

    # -- validators -------------------------------------------------------
    @field_validator("allowed_folders", "read_only_folders", mode="before")
    @classmethod
    def _parse_folder_list(cls, value: Any) -> Any:
        if isinstance(value, str):
            return _split_paths(value)
        return value

    @field_validator("allowed_domains", "allowed_applications", mode="before")
    @classmethod
    def _parse_csv(cls, value: Any) -> Any:
        if isinstance(value, str):
            return [v.strip().lower() for v in value.split(",") if v.strip()]
        return value

    @field_validator("allowed_domains")
    @classmethod
    def _normalise_domains(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for item in value:
            domain = item.strip().lower()
            domain = domain.removeprefix("https://").removeprefix("http://")
            domain = domain.split("/")[0].strip()
            if domain and domain not in cleaned:
                cleaned.append(domain)
        return cleaned

    @field_validator("data_dir", mode="before")
    @classmethod
    def _blank_data_dir_means_default(cls, value: Any) -> Any:
        if value in (None, "", " "):
            return default_data_dir()
        return value

    @field_validator("speech_language")
    @classmethod
    def _check_language(cls, value: str) -> str:
        allowed = {"auto", "hi-IN", "en-IN", "en-US", "en-GB", "hi"}
        if value not in allowed:
            raise ValueError(f"speech_language must be one of {sorted(allowed)}")
        return value

    # -- derived paths ----------------------------------------------------
    @computed_field  # type: ignore[prop-decorator]
    @property
    def database_path(self) -> Path:
        return self.data_dir / "pluto.db"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def log_dir(self) -> Path:
        return self.data_dir / "logs"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def evidence_dir(self) -> Path:
        return self.data_dir / "evidence"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def browser_profile_dir(self) -> Path:
        return self.data_dir / "browser_profile"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def skills_dir(self) -> Path:
        return self.data_dir / "skills"

    @property
    def credential_fallback_path(self) -> Path:
        return self.data_dir / ".pluto_secrets" / "credentials.env"

    # -- helpers ----------------------------------------------------------
    def ensure_directories(self) -> None:
        """Create the writable directories this configuration depends on."""
        for path in (
            self.data_dir,
            self.log_dir,
            self.evidence_dir,
            self.skills_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)

    def safe_dump(self) -> dict[str, Any]:
        """Configuration snapshot for diagnostics — contains no secrets."""
        data = self.model_dump(mode="json")
        data["_runtime"] = {
            "platform": sys.platform,
            "python": sys.version.split()[0],
            "is_windows": sys.platform == "win32",
        }
        return data

    def with_overrides(self, **kwargs: Any) -> Settings:
        """Return a copy with *kwargs* applied, validated."""
        merged = self.model_dump()
        merged.update(kwargs)
        return Settings(**merged)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings singleton."""
    return Settings()


def reload_settings() -> Settings:
    """Drop the cached settings and re-read the environment."""
    get_settings.cache_clear()
    return get_settings()

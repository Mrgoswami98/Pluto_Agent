"""Tests for configuration and for the redacting logger."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest
from pydantic import ValidationError

from pluto.core.config import Settings, default_data_dir, get_settings, reload_settings
from pluto.core.constants import AutonomyMode
from pluto.core.logging_config import (
    configure_logging,
    get_logger,
    task_context,
)


class TestSettingsDefaults:
    def test_defaults_are_safe(self):
        s = Settings(_env_file=None)
        assert s.allowed_folders == [], "no folder may be granted by default"
        assert s.allowed_domains == [], "no domain may be allowed by default"
        assert s.autonomy_mode == AutonomyMode.ASSISTED
        assert s.browser_headless is False, "automation must be visible"
        assert s.windows_automation_enabled is False
        assert s.screenshot_enabled is False

    def test_data_dir_is_outside_install_dir(self):
        s = Settings(_env_file=None)
        assert s.data_dir == default_data_dir()
        assert s.database_path.name == "pluto.db"
        assert s.log_dir.name == "logs"

    def test_derived_paths_live_under_data_dir(self, tmp_path: Path):
        s = Settings(_env_file=None, data_dir=tmp_path)
        for p in (s.database_path, s.log_dir, s.evidence_dir, s.skills_dir):
            assert str(p).startswith(str(tmp_path))


class TestSettingsParsing:
    def test_folder_list_parsed_from_string(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("PLUTO_ALLOWED_FOLDERS", "/tmp/a:/tmp/b")
        s = Settings(_env_file=None)
        assert len(s.allowed_folders) == 2

    def test_semicolon_separated_folders_parsed(self):
        s = Settings(_env_file=None, allowed_folders=r"C:\One;C:\Two")
        assert len(s.allowed_folders) == 2

    def test_domains_normalised(self):
        s = Settings(_env_file=None, allowed_domains="HTTPS://Example.COM/path, foo.org")
        assert s.allowed_domains == ["example.com", "foo.org"]

    def test_duplicate_domains_collapsed(self):
        s = Settings(_env_file=None, allowed_domains="a.com,A.com,https://a.com")
        assert s.allowed_domains == ["a.com"]

    def test_blank_data_dir_falls_back_to_default(self):
        s = Settings(_env_file=None, data_dir="")
        assert s.data_dir == default_data_dir()

    def test_env_prefix_applied(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("PLUTO_LOG_LEVEL", "DEBUG")
        monkeypatch.setenv("PLUTO_MAX_STEPS_PER_TASK", "7")
        s = Settings(_env_file=None)
        assert s.log_level == "DEBUG"
        assert s.max_steps_per_task == 7


class TestSettingsValidation:
    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("max_steps_per_task", 0),
            ("max_steps_per_task", 500),
            ("tool_timeout_seconds", 0),
            ("temperature", 1.5),
            ("max_tokens", 10),
            ("api_max_retries", 99),
            ("retention_days", 0),
        ],
    )
    def test_out_of_range_rejected(self, field: str, value: object):
        with pytest.raises(ValidationError):
            Settings(_env_file=None, **{field: value})

    def test_invalid_autonomy_mode_rejected(self):
        with pytest.raises(ValidationError):
            Settings(_env_file=None, autonomy_mode="god_mode")

    def test_invalid_speech_language_rejected(self):
        with pytest.raises(ValidationError):
            Settings(_env_file=None, speech_language="klingon")

    def test_valid_autonomy_modes_accepted(self):
        for mode in ("observe", "assisted", "workflow", "supervised"):
            assert Settings(_env_file=None, autonomy_mode=mode).autonomy_mode == mode


class TestSettingsHelpers:
    def test_safe_dump_contains_no_api_key_field(self):
        dump = Settings(_env_file=None).safe_dump()
        flat = json.dumps(dump).lower()
        assert "anthropic_api_key" not in flat
        assert "sk-ant" not in flat

    def test_safe_dump_reports_runtime(self):
        dump = Settings(_env_file=None).safe_dump()
        assert "platform" in dump["_runtime"]
        assert "is_windows" in dump["_runtime"]

    def test_ensure_directories_creates_them(self, tmp_path: Path):
        s = Settings(_env_file=None, data_dir=tmp_path / "pluto")
        s.ensure_directories()
        assert s.log_dir.is_dir()
        assert s.evidence_dir.is_dir()
        assert s.skills_dir.is_dir()

    def test_with_overrides_returns_new_validated_copy(self):
        s = Settings(_env_file=None)
        other = s.with_overrides(max_steps_per_task=11)
        assert other.max_steps_per_task == 11
        assert s.max_steps_per_task != 11

    def test_singleton_is_cached_and_reloadable(self):
        assert get_settings() is get_settings()
        assert reload_settings() is get_settings()


class TestLoggingRedaction:
    """A secret must never survive the trip to a log file."""

    @pytest.fixture()
    def log_dir(self, tmp_path: Path) -> Path:
        d = tmp_path / "logs"
        configure_logging(log_dir=d, level="DEBUG", console=False, force=True)
        return d

    @staticmethod
    def _read(log_dir: Path) -> str:
        for handler in logging.getLogger().handlers:
            handler.flush()
        return (log_dir / "pluto.jsonl").read_text("utf-8")

    def test_api_key_in_message_is_redacted(self, log_dir: Path):
        get_logger("test").info("using key sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWX now")
        content = self._read(log_dir)
        assert "sk-ant-api03" not in content
        assert "REDACTED" in content

    def test_secret_in_percent_arg_is_redacted(self, log_dir: Path):
        get_logger("test").info("token=%s", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123")
        assert "ghp_ABCDEF" not in self._read(log_dir)

    def test_secret_in_structured_extra_is_redacted(self, log_dir: Path):
        get_logger("test").info(
            "calling api", extra={"payload": {"api_key": "sk-ant-secret-value-123456"}}
        )
        content = self._read(log_dir)
        assert "sk-ant-secret-value" not in content

    def test_secret_in_exception_traceback_is_redacted(self, log_dir: Path):
        try:
            raise ValueError("failed with key sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUV")
        except ValueError:
            get_logger("test").exception("boom")
        assert "sk-ant-api03" not in self._read(log_dir)

    def test_output_is_valid_jsonl(self, log_dir: Path):
        get_logger("test").warning("something happened", extra={"count": 3})
        for line in self._read(log_dir).strip().splitlines():
            record = json.loads(line)
            assert {"ts", "level", "logger", "message"} <= record.keys()

    def test_task_context_tags_records(self, log_dir: Path):
        with task_context("task-abc-123", "step-9"):
            get_logger("test").info("inside task")
        records = [json.loads(ln) for ln in self._read(log_dir).strip().splitlines()]
        tagged = [r for r in records if r.get("task_id") == "task-abc-123"]
        assert tagged and tagged[0]["step_id"] == "step-9"

    def test_context_cleared_after_exit(self, log_dir: Path):
        with task_context("task-xyz"):
            pass
        get_logger("test").info("outside")
        records = [json.loads(ln) for ln in self._read(log_dir).strip().splitlines()]
        assert records[-1].get("task_id") is None

    def test_rotation_configured(self, tmp_path: Path):
        configure_logging(
            log_dir=tmp_path / "l", level="INFO", max_bytes=1024,
            backup_count=2, console=False, force=True,
        )
        handlers = [
            h for h in logging.getLogger().handlers
            if isinstance(h, logging.handlers.RotatingFileHandler)
        ]
        assert handlers and handlers[0].backupCount == 2

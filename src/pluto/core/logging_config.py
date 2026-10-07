"""Structured logging with automatic secret redaction.

Every record passes through :class:`RedactingFilter` before it reaches a
handler, so a stray ``logger.info(f"calling with {payload}")`` cannot leak an
API key into ``pluto.log``.

Two handlers are installed:

* a rotating JSON-lines file handler — machine-readable, for the diagnostics
  viewer and for export;
* a console handler — human-readable, used during development.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import sys
import time
from contextvars import ContextVar
from pathlib import Path
from typing import Any

from pluto.security.secrets import redact, redact_mapping

#: Correlates every log line emitted while one task runs.
current_task_id: ContextVar[str | None] = ContextVar("current_task_id", default=None)
current_step_id: ContextVar[str | None] = ContextVar("current_step_id", default=None)

_RESERVED = frozenset(
    {
        "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
        "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
        "created", "msecs", "relativeCreated", "thread", "threadName",
        "processName", "process", "taskName", "message", "asctime",
    }
)


class RedactingFilter(logging.Filter):
    """Scrubs secrets from the message, args and structured extras."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            # Render first so %-style args are included in the scan.
            rendered = record.getMessage()
        except Exception:  # pragma: no cover - broken format string
            rendered = str(record.msg)

        record.msg = redact(rendered)
        record.args = ()

        for key, value in list(record.__dict__.items()):
            if key in _RESERVED or key.startswith("_"):
                continue
            if isinstance(value, str):
                record.__dict__[key] = redact(value)
            elif isinstance(value, dict):
                record.__dict__[key] = redact_mapping(value)

        if record.exc_text:
            record.exc_text = redact(record.exc_text)
        return True


class ContextFilter(logging.Filter):
    """Attaches the active task/step ids to every record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.task_id = current_task_id.get()
        record.step_id = current_step_id.get()
        return True


class JsonFormatter(logging.Formatter):
    """One JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(record.created))
            + f".{int(record.msecs):03d}",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if getattr(record, "task_id", None):
            payload["task_id"] = record.task_id
        if getattr(record, "step_id", None):
            payload["step_id"] = record.step_id

        extras = {
            k: v
            for k, v in record.__dict__.items()
            if k not in _RESERVED
            and not k.startswith("_")
            and k not in {"task_id", "step_id"}
        }
        if extras:
            payload["extra"] = _jsonable(extras)

        if record.exc_info:
            payload["exception"] = redact(self.formatException(record.exc_info))

        return json.dumps(payload, ensure_ascii=False, default=str)


class ConsoleFormatter(logging.Formatter):
    """Compact, readable output for a terminal."""

    def __init__(self) -> None:
        super().__init__(
            fmt="%(asctime)s %(levelname)-7s %(name)-28s %(message)s",
            datefmt="%H:%M:%S",
        )

    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        task = getattr(record, "task_id", None)
        if task:
            base = f"{base}  [task {str(task)[:8]}]"
        return base


def _jsonable(value: Any, _depth: int = 0) -> Any:
    """Best-effort conversion to something ``json.dumps`` accepts."""
    if _depth > 6:
        return "..."
    if isinstance(value, (str, int, float, bool, type(None))):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(k): _jsonable(v, _depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v, _depth + 1) for v in value]
    return str(value)


_configured = False


def configure_logging(
    *,
    log_dir: Path | None = None,
    level: str = "INFO",
    max_bytes: int = 5 * 1024 * 1024,
    backup_count: int = 5,
    console: bool = True,
    force: bool = False,
) -> logging.Logger:
    """Install Pluto's handlers on the root logger. Idempotent."""
    global _configured
    root = logging.getLogger()

    if _configured and not force:
        return logging.getLogger("pluto")

    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()

    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    redacting = RedactingFilter()
    context = ContextFilter()

    if log_dir is not None:
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_dir / "pluto.jsonl",
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setFormatter(JsonFormatter())
        file_handler.addFilter(context)
        file_handler.addFilter(redacting)
        root.addHandler(file_handler)

    if console:
        stream = logging.StreamHandler(sys.stderr)
        stream.setFormatter(ConsoleFormatter())
        stream.addFilter(context)
        stream.addFilter(redacting)
        root.addHandler(stream)

    # Third-party chatter stays out of the way.
    for noisy in ("httpx", "httpcore", "urllib3", "anthropic", "asyncio", "PIL"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    _configured = True
    return logging.getLogger("pluto")


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced logger, e.g. ``get_logger("tools.file")``."""
    return logging.getLogger(name if name.startswith("pluto") else f"pluto.{name}")


class task_context:  # noqa: N801 - used as a context manager, reads better lowercase
    """Scope log records to a task (and optionally a step)."""

    def __init__(self, task_id: str, step_id: str | None = None) -> None:
        self._task_id = task_id
        self._step_id = step_id
        self._tokens: list[Any] = []

    def __enter__(self) -> task_context:
        self._tokens.append(current_task_id.set(self._task_id))
        if self._step_id is not None:
            self._tokens.append(current_step_id.set(self._step_id))
        return self

    def __exit__(self, *exc: object) -> None:
        for token in reversed(self._tokens):
            try:
                if token.var is current_task_id:
                    current_task_id.reset(token)
                else:
                    current_step_id.reset(token)
            except ValueError:  # pragma: no cover - cross-context reset
                pass
        self._tokens.clear()

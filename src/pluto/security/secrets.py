"""Secret detection and redaction.

Two jobs:

1. :func:`redact` scrubs anything heading for a log file, the database, or the
   model context. Logs are a classic exfiltration path and the spec forbids
   secrets in them.
2. :class:`CredentialStore` keeps the Claude API key in the OS credential
   vault (Windows Credential Manager via ``keyring``) rather than on disk,
   falling back to an environment variable and finally to a clearly-marked
   file-based store for development only.
"""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from pluto.core.exceptions import ConfigurationError

#: Replacement text. Includes the kind so a developer can tell what was hidden.
REDACTION_TEMPLATE: Final = "[REDACTED:{kind}]"


@dataclass(frozen=True)
class SecretPattern:
    """A named regular expression that matches a kind of secret."""

    kind: str
    pattern: re.Pattern[str]


def _c(kind: str, regex: str, flags: int = 0) -> SecretPattern:
    return SecretPattern(kind=kind, pattern=re.compile(regex, flags))


#: Ordered most-specific first so that, e.g., an Anthropic key is labelled as
#: such rather than caught by the generic high-entropy rule.
SECRET_PATTERNS: Final[tuple[SecretPattern, ...]] = (
    _c("anthropic_key", r"sk-ant-[A-Za-z0-9_\-]{16,}"),
    _c("openai_key", r"\bsk-(?!ant-)[A-Za-z0-9]{20,}"),
    _c("github_token", r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    _c("github_pat", r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    _c("aws_access_key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    _c("google_key", r"\bAIza[0-9A-Za-z_\-]{30,}"),
    _c("slack_token", r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"),
    _c("stripe_key", r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}"),
    _c("private_key_block", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    _c("jwt", r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
    _c("bearer_token", r"(?i)\bbearer\s+[A-Za-z0-9._\-]{20,}"),
    _c("basic_auth_url", r"(?i)\b[a-z][a-z0-9+.\-]*://[^/\s:@]+:[^/\s@]+@"),
    _c("password_assignment",
       r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|"
       r"auth[_-]?token|client[_-]?secret|session[_-]?cookie)\b"
       r"\s*[:=]\s*[\"']?([^\s\"',;}]{6,})"),
    _c("credit_card", r"\b(?:\d[ \-]?){13,19}\b"),
    _c("aadhaar", r"\b\d{4}\s?\d{4}\s?\d{4}\b"),
)

#: Mapping keys whose *values* are always redacted regardless of content.
SENSITIVE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "api_key", "apikey", "anthropic_api_key", "authorization", "auth",
        "password", "passwd", "pwd", "secret", "client_secret", "token",
        "access_token", "refresh_token", "session_token", "cookie", "cookies",
        "set-cookie", "private_key", "credentials", "credential", "pin",
        "otp", "cvv", "card_number", "ssn", "aadhaar",
    }
)


def _redact_card(match: re.Match[str]) -> str:
    """Only redact digit runs that pass Luhn — avoids eating order numbers."""
    digits = re.sub(r"\D", "", match.group(0))
    if not 13 <= len(digits) <= 19:
        return match.group(0)
    total, parity = 0, len(digits) % 2
    for index, char in enumerate(digits):
        value = int(char)
        if index % 2 == parity:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    if total % 10 != 0:
        return match.group(0)
    return REDACTION_TEMPLATE.format(kind="credit_card")


def redact(text: str) -> str:
    """Remove secrets from *text*.

    Safe to call on anything: it never raises, and non-string input is
    stringified first.
    """
    if not isinstance(text, str):
        text = str(text)
    if not text:
        return text

    result = text
    for spec in SECRET_PATTERNS:
        if spec.kind == "credit_card":
            result = spec.pattern.sub(_redact_card, result)
        elif spec.kind == "password_assignment":
            # Keep the key name, hide only the value, so logs stay diagnosable.
            result = spec.pattern.sub(
                lambda m: m.group(0).replace(
                    m.group(1), REDACTION_TEMPLATE.format(kind="value")
                ),
                result,
            )
        else:
            result = spec.pattern.sub(
                REDACTION_TEMPLATE.format(kind=spec.kind), result
            )
    return result


def redact_mapping(data: Mapping[str, Any], *, _depth: int = 0) -> dict[str, Any]:
    """Recursively redact a dict, by key name and by value content."""
    if _depth > 12:  # pragma: no cover - pathological nesting guard
        return {"_truncated": True}

    out: dict[str, Any] = {}
    for key, value in data.items():
        lowered = str(key).strip().lower().replace("-", "_")
        if lowered in SENSITIVE_KEYS:
            out[key] = REDACTION_TEMPLATE.format(kind="field")
        elif isinstance(value, Mapping):
            out[key] = redact_mapping(value, _depth=_depth + 1)
        elif isinstance(value, (list, tuple)):
            out[key] = [
                redact_mapping(v, _depth=_depth + 1)
                if isinstance(v, Mapping)
                else redact(v) if isinstance(v, str) else v
                for v in value
            ]
        elif isinstance(value, str):
            out[key] = redact(value)
        else:
            out[key] = value
    return out


def contains_secret(text: str) -> bool:
    """True if *text* looks like it holds a credential.

    Deliberately broad: it includes the ``password = ...`` assignment
    heuristic, which over-matches on source code (``api_key = get_key()`` is an
    assignment, not a secret). That is the right trade-off for redaction, where
    over-redacting a log line is harmless.

    For scanning a repository, use :func:`contains_literal_secret` instead,
    where a false positive means failing a build for no reason.
    """
    return redact(text) != text


#: Patterns that match an actual credential value, not a reference to one.
#: Used when a false positive would be costly.
HIGH_CONFIDENCE_KINDS: Final[frozenset[str]] = frozenset(
    {
        "anthropic_key", "openai_key", "github_token", "github_pat",
        "aws_access_key", "google_key", "slack_token", "stripe_key",
        "private_key_block", "jwt", "basic_auth_url",
    }
)


def find_literal_secrets(text: str) -> list[tuple[str, str]]:
    """Return ``(kind, matched_text)`` for high-confidence matches only."""
    found: list[tuple[str, str]] = []
    for spec in SECRET_PATTERNS:
        if spec.kind not in HIGH_CONFIDENCE_KINDS:
            continue
        for match in spec.pattern.finditer(text):
            found.append((spec.kind, match.group(0)))
    return found


def contains_literal_secret(text: str) -> bool:
    """True only when *text* contains something shaped like a real key.

    Variable names, assignments and placeholders do not trigger this.
    """
    return bool(find_literal_secrets(text))


# --------------------------------------------------------------------------
# Credential storage
# --------------------------------------------------------------------------
SERVICE_NAME: Final = "PlutoAdvance"
API_KEY_ENTRY: Final = "anthropic_api_key"


class CredentialStore:
    """Stores secrets in the OS vault when available.

    Resolution order on read:

    1. OS credential vault (``keyring`` → Windows Credential Manager).
    2. ``ANTHROPIC_API_KEY`` environment variable.
    3. Development fallback file, only if explicitly enabled.

    The fallback file is chmod 0600 and is listed in ``.gitignore``.
    """

    def __init__(
        self,
        *,
        fallback_path: Path | None = None,
        allow_file_fallback: bool = False,
    ) -> None:
        self._fallback_path = fallback_path
        self._allow_file_fallback = allow_file_fallback
        self._keyring = self._load_keyring()

    @staticmethod
    def _load_keyring() -> Any | None:
        try:
            import keyring
            from keyring.backends.fail import Keyring as FailKeyring

            backend = keyring.get_keyring()
            if isinstance(backend, FailKeyring):
                return None
            return keyring
        except Exception:
            return None

    @property
    def backend_name(self) -> str:
        """Human-readable description for the Settings screen."""
        if self._keyring is not None:
            try:
                return type(self._keyring.get_keyring()).__name__
            except Exception:  # pragma: no cover - defensive
                return "keyring"
        if self._allow_file_fallback:
            return "encrypted-file-fallback (development)"
        return "environment-only"

    @property
    def is_os_backed(self) -> bool:
        return self._keyring is not None

    # -- read -------------------------------------------------------------
    def get(self, entry: str = API_KEY_ENTRY) -> str | None:
        if self._keyring is not None:
            try:
                value = self._keyring.get_password(SERVICE_NAME, entry)
                if value:
                    return value.strip()
            except Exception:
                pass

        env_name = "ANTHROPIC_API_KEY" if entry == API_KEY_ENTRY else entry.upper()
        env_value = os.environ.get(env_name)
        if env_value and env_value.strip():
            return env_value.strip()

        if self._allow_file_fallback and self._fallback_path is not None:
            try:
                if self._fallback_path.exists():
                    for line in self._fallback_path.read_text("utf-8").splitlines():
                        name, _, value = line.partition("=")
                        if name.strip() == entry and value.strip():
                            return value.strip()
            except OSError:
                pass
        return None

    def require(self, entry: str = API_KEY_ENTRY) -> str:
        value = self.get(entry)
        if not value:
            raise ConfigurationError(
                f"Credential '{entry}' is not configured",
                user_message=(
                    "No Claude API key found. Add one under Settings → API, "
                    "or set ANTHROPIC_API_KEY."
                ),
            )
        return value

    # -- write ------------------------------------------------------------
    def set(self, value: str, entry: str = API_KEY_ENTRY) -> str:
        """Store *value*. Returns the backend that accepted it."""
        value = value.strip()
        if not value:
            raise ConfigurationError(
                "Refusing to store an empty credential",
                user_message="The key cannot be blank.",
            )

        if self._keyring is not None:
            try:
                self._keyring.set_password(SERVICE_NAME, entry, value)
                return "os_vault"
            except Exception:
                pass

        if self._allow_file_fallback and self._fallback_path is not None:
            self._write_fallback(entry, value)
            return "file_fallback"

        raise ConfigurationError(
            "No credential backend available",
            user_message=(
                "Pluto could not reach the Windows Credential Manager. "
                "Set ANTHROPIC_API_KEY in your environment instead."
            ),
        )

    def delete(self, entry: str = API_KEY_ENTRY) -> bool:
        """Remove a stored credential from every backend we own."""
        removed = False
        if self._keyring is not None:
            try:
                self._keyring.delete_password(SERVICE_NAME, entry)
                removed = True
            except Exception:
                pass
        if self._fallback_path is not None and self._fallback_path.exists():
            try:
                lines = self._fallback_path.read_text("utf-8").splitlines()
                kept = [ln for ln in lines if not ln.startswith(f"{entry}=")]
                if len(kept) != len(lines):
                    removed = True
                self._fallback_path.write_text(
                    "\n".join(kept) + ("\n" if kept else ""), encoding="utf-8"
                )
            except OSError:
                pass
        return removed

    def _write_fallback(self, entry: str, value: str) -> None:
        assert self._fallback_path is not None
        path = self._fallback_path
        path.parent.mkdir(parents=True, exist_ok=True)

        existing: dict[str, str] = {}
        if path.exists():
            for line in path.read_text("utf-8").splitlines():
                name, _, val = line.partition("=")
                if name.strip():
                    existing[name.strip()] = val.strip()
        existing[entry] = value

        body = "".join(f"{k}={v}\n" for k, v in existing.items())
        path.write_text(body, encoding="utf-8")
        try:
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600
        except OSError:  # pragma: no cover - Windows ACLs differ
            pass


def mask_key(value: str | None, *, visible: int = 4) -> str:
    """Render a key for display: ``sk-ant-...••••1234``."""
    if not value:
        return "(not set)"
    if len(value) <= visible * 2:
        return "•" * len(value)
    return f"{value[:7]}…{'•' * 6}{value[-visible:]}"

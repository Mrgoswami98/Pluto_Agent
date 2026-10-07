"""Tests for secret detection, redaction and credential storage."""

from __future__ import annotations

from pathlib import Path

import pytest

from pluto.core.exceptions import ConfigurationError
from pluto.security.secrets import (
    API_KEY_ENTRY,
    CredentialStore,
    contains_secret,
    mask_key,
    redact,
    redact_mapping,
)


class TestRedactKnownKeyShapes:
    @pytest.mark.parametrize(
        ("secret", "label"),
        [
            ("sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", "anthropic_key"),
            ("ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", "github_token"),
            ("github_pat_11ABCDEFG0aBcDeFgHiJkLmNoPqRsTuVwXyZ", "github_pat"),
            ("AKIAIOSFODNN7EXAMPLE", "aws_access_key"),
            ("AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q", "google_key"),
            ("xoxb-123456789012-abcdefghijklmnop", "slack_token"),
            ("sk_live_AbCdEfGhIjKlMnOpQrStUvWx", "stripe_key"),
        ],
    )
    def test_key_is_removed_and_labelled(self, secret: str, label: str):
        text = f"the key is {secret} ok"
        result = redact(text)
        assert secret not in result
        assert label in result

    def test_jwt_redacted(self):
        jwt = (
            "eyJhbGciOiJIUzI1NiJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        assert jwt not in redact(f"Authorization context {jwt}")

    def test_bearer_header_redacted(self):
        out = redact("Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456")
        assert "abcdefghijklmnopqrstuvwxyz123456" not in out

    def test_private_key_block_redacted(self):
        out = redact("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIB...")
        assert "BEGIN RSA PRIVATE KEY" not in out

    def test_url_with_inline_credentials_redacted(self):
        out = redact("clone https://admin:hunter2@git.example.com/repo.git")
        assert "hunter2" not in out


class TestRedactAssignments:
    @pytest.mark.parametrize(
        "line",
        [
            "password = SuperSecret123",
            'api_key: "abc123xyz789"',
            "client_secret=qwertyuiop12",
            "ACCESS_TOKEN = 'tok_abcdef123456'",
            "session_cookie: ab12cd34ef56",
        ],
    )
    def test_value_hidden_key_name_kept(self, line: str):
        out = redact(line)
        assert "REDACTED" in out
        # The key name survives so logs remain diagnosable.
        assert any(word in out.lower() for word in ("password", "key", "secret", "token", "cookie"))

    def test_short_values_not_matched(self):
        # "pwd = ab" is too short to be a credential; avoid noisy redaction.
        assert redact("pwd = ab") == "pwd = ab"


class TestCreditCardLuhn:
    def test_valid_card_redacted(self):
        assert "4111111111111111" not in redact("card 4111111111111111")

    def test_spaced_valid_card_redacted(self):
        assert "REDACTED" in redact("card 4111 1111 1111 1111")

    def test_invalid_luhn_left_alone(self):
        # An order number that happens to be 16 digits must survive.
        text = "order 1234567890123456"
        assert redact(text) == text

    def test_short_digit_run_left_alone(self):
        assert redact("quantity 12345") == "quantity 12345"


class TestRedactSafety:
    def test_empty_string(self):
        assert redact("") == ""

    def test_plain_text_unchanged(self):
        text = "Open the Q3 report and summarise the revenue column."
        assert redact(text) == text

    def test_non_string_input_does_not_raise(self):
        assert redact(12345) == "12345"  # type: ignore[arg-type]

    def test_multiple_secrets_all_removed(self):
        text = "key sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUV and token ghp_ABCDEFGHIJKLMNOPQRSTUV"
        out = redact(text)
        assert "sk-ant-api03" not in out
        assert "ghp_" not in out

    def test_contains_secret_detects(self):
        assert contains_secret("sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWX") is True
        assert contains_secret("just some ordinary notes") is False


class TestRedactMapping:
    def test_sensitive_key_redacted_by_name(self):
        out = redact_mapping({"api_key": "anything-at-all", "model": "claude"})
        assert out["api_key"] == "[REDACTED:field]"
        assert out["model"] == "claude"

    def test_key_matching_is_case_and_dash_insensitive(self):
        out = redact_mapping({"API-KEY": "x", "Authorization": "y"})
        assert all(v == "[REDACTED:field]" for v in out.values())

    def test_nested_mapping_redacted(self):
        out = redact_mapping({"outer": {"inner": {"password": "p@ss"}}})
        assert out["outer"]["inner"]["password"] == "[REDACTED:field]"

    def test_list_of_mappings_redacted(self):
        out = redact_mapping({"items": [{"token": "abc"}, {"name": "safe"}]})
        assert out["items"][0]["token"] == "[REDACTED:field]"
        assert out["items"][1]["name"] == "safe"

    def test_secret_in_value_of_innocuous_key_still_redacted(self):
        out = redact_mapping({"note": "my key is sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUV"})
        assert "sk-ant-api03" not in out["note"]

    def test_non_string_values_preserved(self):
        out = redact_mapping({"count": 7, "ok": True, "ratio": 1.5})
        assert out == {"count": 7, "ok": True, "ratio": 1.5}


class TestMaskKey:
    def test_masks_middle(self):
        masked = mask_key("sk-ant-api03-SECRETSECRET1234")
        assert "SECRETSECRET" not in masked
        assert masked.endswith("1234")

    def test_none_renders_placeholder(self):
        assert mask_key(None) == "(not set)"

    def test_short_value_fully_masked(self):
        assert set(mask_key("abc")) == {"•"}


class TestCredentialStore:
    """The store must never silently lose a key or expose one."""

    @pytest.fixture()
    def store(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> CredentialStore:
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        s = CredentialStore(
            fallback_path=tmp_path / "secrets.env", allow_file_fallback=True
        )
        # Force the file backend so the test does not depend on a real OS vault.
        s._keyring = None
        return s

    def test_roundtrip_via_fallback(self, store: CredentialStore):
        backend = store.set("sk-ant-test-key-value-123456")
        assert backend == "file_fallback"
        assert store.get() == "sk-ant-test-key-value-123456"

    def test_fallback_file_is_not_world_readable(
        self, store: CredentialStore, tmp_path: Path
    ):
        store.set("sk-ant-test-key-value-123456")
        mode = (tmp_path / "secrets.env").stat().st_mode & 0o777
        assert mode & 0o077 == 0, "secret file must not be group/world readable"

    def test_environment_variable_is_read(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-from-env-123456")
        s = CredentialStore(fallback_path=tmp_path / "s.env")
        s._keyring = None
        assert s.get() == "sk-ant-from-env-123456"

    def test_missing_key_returns_none(self, store: CredentialStore):
        assert store.get() is None

    def test_require_raises_actionable_error(self, store: CredentialStore):
        with pytest.raises(ConfigurationError) as exc:
            store.require()
        assert "Settings" in exc.value.user_message

    def test_empty_value_rejected(self, store: CredentialStore):
        with pytest.raises(ConfigurationError):
            store.set("   ")

    def test_delete_removes_key(self, store: CredentialStore):
        store.set("sk-ant-test-key-value-123456")
        assert store.delete() is True
        assert store.get() is None

    def test_no_backend_available_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        s = CredentialStore(allow_file_fallback=False)
        s._keyring = None
        with pytest.raises(ConfigurationError):
            s.set("sk-ant-value-123456")

    def test_multiple_entries_coexist(self, store: CredentialStore):
        store.set("sk-ant-main-123456", API_KEY_ENTRY)
        store.set("speech-key-abcdef", "speech_api_key")
        assert store.get(API_KEY_ENTRY) == "sk-ant-main-123456"
        assert store.get("speech_api_key") == "speech-key-abcdef"

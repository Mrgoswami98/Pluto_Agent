"""Live Claude API tests.

These are **opt-in** and need a real key. They are skipped by default, and a
skip is reported as a skip — never as a pass.

    export ANTHROPIC_API_KEY="sk-ant-..."
    pytest -m integration -v
"""

from __future__ import annotations

import os

import pytest

from pluto.ai.client import ClaudeClient
from pluto.ai.planner import Planner
from pluto.ai.prompts import build_system_prompt
from pluto.core.constants import AutonomyMode
from pluto.security.secrets import CredentialStore

pytestmark = pytest.mark.integration

HAS_KEY = bool(os.environ.get("ANTHROPIC_API_KEY"))
needs_key = pytest.mark.skipif(
    not HAS_KEY,
    reason="set ANTHROPIC_API_KEY to run live API tests",
)


@pytest.fixture()
def client() -> ClaudeClient:
    return ClaudeClient(credential_store=CredentialStore(), max_tokens=512)


@needs_key
class TestLiveClaudeAPI:
    def test_connection_succeeds(self, client: ClaudeClient):
        ok, message = client.test_connection()
        assert ok, f"connection failed: {message}"

    def test_simple_exchange(self, client: ClaudeClient):
        response = client.send(
            [{"role": "user", "content": "Reply with exactly: PLUTO_OK"}]
        )
        assert "PLUTO_OK" in response.text
        assert response.usage["input_tokens"] > 0

    def test_token_accounting_is_recorded(self, client: ClaudeClient):
        before = client.usage.total
        client.send([{"role": "user", "content": "Say hello."}])
        assert client.usage.total > before
        assert client.usage.request_count >= 1

    def test_hindi_is_understood(self, client: ClaudeClient):
        response = client.send(
            [{"role": "user", "content": "Namaste, aap kaise ho? Hinglish me jawab do."}],
            system=build_system_prompt(autonomy_mode=AutonomyMode.ASSISTED),
        )
        assert response.text.strip(), "no reply to a Hinglish prompt"

    def test_streaming_yields_text(self, client: ClaudeClient):
        chunks = list(
            client.stream([{"role": "user", "content": "Count from 1 to 5."}])
        )
        assert chunks, "the stream produced nothing"
        assert "".join(chunks).strip()

    def test_planner_produces_a_valid_plan(self, client: ClaudeClient, tmp_path):
        """The real end-to-end check: a live model, a real plan, real validation."""
        from pluto.security.paths import PathGuard
        from pluto.security.permissions import PermissionEngine
        from pluto.tools.files import build_file_tools
        from pluto.tools.registry import ToolRegistry

        workspace = tmp_path / "ws"
        workspace.mkdir()
        (workspace / "data.txt").write_text("hello", encoding="utf-8")

        registry = ToolRegistry(PermissionEngine())
        registry.register_all(build_file_tools(PathGuard(allowed_roots=[workspace])))

        planner = Planner(client, registry, max_steps=5)
        result = planner.plan(
            f"List the files in {workspace}",
            system_prompt=build_system_prompt(
                autonomy_mode=AutonomyMode.ASSISTED,
                allowed_folders=[str(workspace)],
            ),
        )
        registry.shutdown()

        assert result.task is not None, (
            f"the model asked for clarification instead: {result.clarification_needed}"
        )
        assert result.task.steps
        assert all(
            s.tool_name is None or registry.has(s.tool_name)
            for s in result.task.steps
        )


@needs_key
class TestLiveErrorHandling:
    def test_bad_model_name_reports_clearly(self, client: ClaudeClient):
        from pluto.core.exceptions import ModelAPIError

        client.model = "claude-does-not-exist-9"
        with pytest.raises(ModelAPIError) as exc:
            client.send([{"role": "user", "content": "hi"}])
        assert "model" in exc.value.user_message.lower()

    def test_bad_key_is_not_retried(self, tmp_path, monkeypatch):
        from pluto.core.exceptions import ModelAPIError

        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-invalid-key-for-testing-00000")
        bad = ClaudeClient(credential_store=CredentialStore(), max_retries=3)
        with pytest.raises(ModelAPIError) as exc:
            bad.send([{"role": "user", "content": "hi"}])
        assert "key" in exc.value.user_message.lower()

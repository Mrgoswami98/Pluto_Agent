"""Claude API client.

Wraps the Anthropic SDK with the behaviour Pluto needs:

* a single place where the API key is fetched (from the credential store, never
  from a config dump),
* retry with exponential backoff that respects ``retry-after``,
* token accounting per task,
* cancellation checks between retries,
* errors mapped to Pluto's exception types with messages a user can act on.

The SDK already retries some failures; we set ``max_retries=0`` on the client
and do it here so that backoff, cancellation and accounting stay in one place.
"""

from __future__ import annotations

import random
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from pluto.core.exceptions import (
    MissingAPIKeyError,
    ModelAPIError,
    RateLimitError,
    TaskCancelledError,
)
from pluto.core.logging_config import get_logger
from pluto.security.secrets import CredentialStore

log = get_logger("ai.client")

#: Status codes worth retrying.
_RETRYABLE_STATUS = frozenset({408, 409, 429, 500, 502, 503, 504, 529})


@dataclass
class TokenUsage:
    """Running token count, for budget enforcement and the usage display."""

    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_creation_tokens: int = 0
    request_count: int = 0

    @property
    def total(self) -> int:
        return self.input_tokens + self.output_tokens

    def add(self, usage: Any) -> None:
        self.input_tokens += getattr(usage, "input_tokens", 0) or 0
        self.output_tokens += getattr(usage, "output_tokens", 0) or 0
        self.cache_read_tokens += getattr(usage, "cache_read_input_tokens", 0) or 0
        self.cache_creation_tokens += (
            getattr(usage, "cache_creation_input_tokens", 0) or 0
        )
        self.request_count += 1

    def snapshot(self) -> dict[str, int]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_read_tokens": self.cache_read_tokens,
            "total_tokens": self.total,
            "requests": self.request_count,
        }


@dataclass
class ModelResponse:
    """A normalised response, independent of the SDK's object shapes."""

    text: str = ""
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    stop_reason: str | None = None
    model: str = ""
    usage: dict[str, int] = field(default_factory=dict)
    raw_content: list[Any] = field(default_factory=list)

    @property
    def wants_tool_use(self) -> bool:
        return bool(self.tool_calls)


class ClaudeClient:
    """Pluto's interface to the Claude API."""

    def __init__(
        self,
        *,
        credential_store: CredentialStore,
        model: str = "claude-sonnet-5-5",
        max_tokens: int = 4096,
        temperature: float = 0.2,
        timeout: float = 120.0,
        max_retries: int = 3,
        base_url: str | None = None,
    ) -> None:
        self._credentials = credential_store
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.timeout = timeout
        self.max_retries = max_retries
        self._base_url = base_url
        self._client: Any = None
        self._lock = threading.Lock()
        self.usage = TokenUsage()

    # -- connection -------------------------------------------------------
    def _build_client(self) -> Any:
        api_key = self._credentials.get()
        if not api_key:
            raise MissingAPIKeyError(
                "No Claude API key configured",
                user_message=(
                    "Pluto needs a Claude API key to think. Add one under "
                    "Settings → API, or set ANTHROPIC_API_KEY."
                ),
            )
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - dependency is required
            raise ModelAPIError(
                "The anthropic package is not installed",
                user_message="Pluto's AI library is missing. Reinstall the application.",
            ) from exc

        kwargs: dict[str, Any] = {
            "api_key": api_key,
            "timeout": self.timeout,
            # Retries are handled here, not in the SDK, so that backoff,
            # cancellation and token accounting live in one place.
            "max_retries": 0,
        }
        if self._base_url:
            kwargs["base_url"] = self._base_url
        return anthropic.Anthropic(**kwargs)

    @property
    def client(self) -> Any:
        with self._lock:
            if self._client is None:
                self._client = self._build_client()
            return self._client

    def reset_connection(self) -> None:
        """Drop the cached client, e.g. after the user changes the key."""
        with self._lock:
            self._client = None

    @property
    def has_api_key(self) -> bool:
        return bool(self._credentials.get())

    def test_connection(self) -> tuple[bool, str]:
        """Cheap round-trip used by Settings. Returns (ok, message)."""
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=16,
                messages=[{"role": "user", "content": "Reply with OK."}],
            )
            text = "".join(
                block.text for block in response.content if block.type == "text"
            )
            return True, f"Connected to {self.model}. Reply: {text.strip()[:40]}"
        except Exception as exc:
            return False, self._describe_error(exc)

    # -- messages ---------------------------------------------------------
    def send(
        self,
        messages: list[dict[str, Any]],
        *,
        system: str | None = None,
        tools: list[dict[str, Any]] | None = None,
        max_tokens: int | None = None,
        temperature: float | None = None,
        cancel_event: threading.Event | None = None,
    ) -> ModelResponse:
        """Send a request, retrying transient failures."""
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens or self.max_tokens,
            "temperature": temperature if temperature is not None else self.temperature,
            "messages": messages,
        }
        if system:
            payload["system"] = system
        if tools:
            payload["tools"] = tools

        last_error: Exception | None = None

        for attempt in range(self.max_retries + 1):
            self._check_cancelled(cancel_event)
            try:
                response = self.client.messages.create(**payload)
            except Exception as exc:
                last_error = exc
                delay = self._retry_delay(exc, attempt)
                if delay is None or attempt >= self.max_retries:
                    raise self._map_error(exc) from exc
                log.warning(
                    "Claude API attempt %s/%s failed (%s); retrying in %.1fs",
                    attempt + 1,
                    self.max_retries + 1,
                    type(exc).__name__,
                    delay,
                )
                self._sleep_cancellably(delay, cancel_event)
                continue

            self.usage.add(getattr(response, "usage", None))
            return self._normalise(response)

        raise self._map_error(last_error) from last_error  # pragma: no cover

    def stream(
        self,
        messages: list[dict[str, Any]],
        *,
        system: str | None = None,
        tools: list[dict[str, Any]] | None = None,
        max_tokens: int | None = None,
        cancel_event: threading.Event | None = None,
    ) -> Iterator[str]:
        """Yield text deltas as they arrive, for the chat view.

        Cancellation is checked between chunks, so pressing Emergency Stop
        stops the stream promptly rather than at the end of the response.
        """
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens or self.max_tokens,
            "temperature": self.temperature,
            "messages": messages,
        }
        if system:
            payload["system"] = system
        if tools:
            payload["tools"] = tools

        try:
            with self.client.messages.stream(**payload) as stream:
                for chunk in stream.text_stream:
                    self._check_cancelled(cancel_event)
                    yield chunk
                final = stream.get_final_message()
                self.usage.add(getattr(final, "usage", None))
        except TaskCancelledError:
            raise
        except Exception as exc:
            raise self._map_error(exc) from exc

    # -- helpers ----------------------------------------------------------
    @staticmethod
    def _normalise(response: Any) -> ModelResponse:
        text_parts: list[str] = []
        tool_calls: list[dict[str, Any]] = []

        for block in getattr(response, "content", []) or []:
            block_type = getattr(block, "type", None)
            if block_type == "text":
                text_parts.append(block.text)
            elif block_type == "tool_use":
                tool_calls.append(
                    {
                        "id": block.id,
                        "name": block.name,
                        "arguments": dict(block.input or {}),
                    }
                )

        usage = getattr(response, "usage", None)
        return ModelResponse(
            text="".join(text_parts),
            tool_calls=tool_calls,
            stop_reason=getattr(response, "stop_reason", None),
            model=getattr(response, "model", ""),
            usage={
                "input_tokens": getattr(usage, "input_tokens", 0) or 0,
                "output_tokens": getattr(usage, "output_tokens", 0) or 0,
            },
            raw_content=list(getattr(response, "content", []) or []),
        )

    @staticmethod
    def _check_cancelled(cancel_event: threading.Event | None) -> None:
        if cancel_event is not None and cancel_event.is_set():
            raise TaskCancelledError(
                "Cancelled while talking to Claude",
                user_message="The task was cancelled.",
            )

    @staticmethod
    def _sleep_cancellably(seconds: float, cancel_event: threading.Event | None) -> None:
        """Sleep in a way that a cancel can interrupt."""
        if cancel_event is not None:
            if cancel_event.wait(timeout=seconds):
                raise TaskCancelledError(
                    "Cancelled while backing off",
                    user_message="The task was cancelled.",
                )
        else:
            time.sleep(seconds)

    def _retry_delay(self, exc: Exception, attempt: int) -> float | None:
        """Seconds to wait, or None if the error is not retryable."""
        status = getattr(exc, "status_code", None)
        name = type(exc).__name__

        retryable = (
            name in {"RateLimitError", "APIConnectionError", "APITimeoutError",
                     "InternalServerError", "OverloadedError", "ServiceUnavailableError",
                     "RetryableError"}
            or (status is not None and status in _RETRYABLE_STATUS)
        )
        if not retryable:
            return None

        # Honour an explicit retry-after header when the server sends one.
        retry_after = self._retry_after_seconds(exc)
        if retry_after is not None:
            return min(retry_after, 60.0)

        # Exponential backoff with jitter, capped.
        base = min(2.0**attempt, 30.0)
        return base + random.uniform(0, base * 0.25)

    @staticmethod
    def _retry_after_seconds(exc: Exception) -> float | None:
        response = getattr(exc, "response", None)
        headers = getattr(response, "headers", None)
        if not headers:
            return None
        for key in ("retry-after", "Retry-After"):
            try:
                value = headers.get(key)
            except AttributeError:
                return None
            if value:
                try:
                    return float(value)
                except (TypeError, ValueError):
                    return None
        return None

    def _map_error(self, exc: Exception | None) -> Exception:
        """Translate an SDK error into a Pluto error with a usable message."""
        if exc is None:  # pragma: no cover - defensive
            return ModelAPIError("Unknown API failure")

        name = type(exc).__name__
        status = getattr(exc, "status_code", None)

        if name == "RateLimitError" or status == 429:
            return RateLimitError(
                f"Rate limited by the Claude API: {exc}",
                user_message=(
                    "Claude is rate-limiting requests right now. Pluto backed off "
                    "and retried, but the limit is still in effect. Try again shortly."
                ),
            )
        if name == "AuthenticationError" or status == 401:
            return ModelAPIError(
                f"Authentication failed: {exc}",
                user_message=(
                    "Claude rejected the API key. Check it under Settings → API."
                ),
            )
        if name == "PermissionDeniedError" or status == 403:
            return ModelAPIError(
                f"Permission denied: {exc}",
                user_message=(
                    "This API key is not allowed to use that model. Check your "
                    "plan at console.anthropic.com."
                ),
            )
        if name == "NotFoundError" or status == 404:
            return ModelAPIError(
                f"Model not found: {exc}",
                user_message=(
                    f"The model '{self.model}' was not found. Pick another model "
                    f"under Settings → API."
                ),
            )
        if name in {"BadRequestError", "UnprocessableEntityError"} or status in (400, 422):
            return ModelAPIError(
                f"Invalid request: {exc}",
                user_message="Pluto sent a request Claude could not accept.",
                detail=str(exc)[:500],
            )
        if name == "RequestTooLargeError" or status == 413:
            return ModelAPIError(
                f"Request too large: {exc}",
                user_message=(
                    "The conversation grew too large for one request. Start a new "
                    "chat or narrow the task."
                ),
            )
        if name in {"APIConnectionError", "APITimeoutError"}:
            return ModelAPIError(
                f"Could not reach the Claude API: {exc}",
                user_message=(
                    "Pluto could not reach Claude. Check your internet connection."
                ),
            )
        if name in {"InternalServerError", "OverloadedError", "ServiceUnavailableError"}:
            return ModelAPIError(
                f"Claude service error: {exc}",
                user_message="Claude's service is having trouble. Try again shortly.",
            )

        return ModelAPIError(
            f"{name}: {exc}",
            user_message=f"The Claude API returned an error: {exc}",
            detail=str(exc)[:500],
        )

    @staticmethod
    def _describe_error(exc: Exception) -> str:
        name = type(exc).__name__
        if name == "AuthenticationError":
            return "The API key was rejected. Check it and try again."
        if name in {"APIConnectionError", "APITimeoutError"}:
            return "Could not reach the Claude API. Check your internet connection."
        if name == "NotFoundError":
            return "That model name was not found."
        if name == "RateLimitError":
            return "Rate limited. Wait a moment and try again."
        return f"{name}: {exc}"

"""A provider backed by the Anthropic Messages API.

When `cache` is set the system prompt is marked with an ephemeral cache_control block,
since a scenario's knowledge is large and reused across a run, so caching it is the
high value target. The client is injectable so the mapping and caching logic test
without the SDK or a key, otherwise it is built lazily and reads ANTHROPIC_API_KEY from
the environment.
"""

from __future__ import annotations

from typing import Any

from opfor.core.providers.base import CompletionResult, Message, Provider, require_completion_text


class AnthropicProvider(Provider):
    def __init__(
        self,
        *,
        api_key: str | None = None,
        api_base: str | None = None,
        client: Any | None = None,
        temperature: float | None = 0.0,
        timeout: float = 240.0,
    ) -> None:
        self._api_key = api_key
        self._api_base = api_base
        self._client = client
        # Temperature 0 for determinism, so the same surface yields the same verdicts.
        self._temperature = temperature
        # A per request deadline, so a hung or rate-limit-stalled call returns to the
        # retry layer to back off rather than holding the slot until a far longer ceiling.
        self._timeout = timeout

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                import anthropic
            except ImportError as exc:
                raise RuntimeError(
                    "the anthropic backend needs the anthropic SDK, install opfor[anthropic]"
                ) from exc
            kwargs: dict[str, Any] = {}
            if self._api_key:
                kwargs["api_key"] = self._api_key
            if self._api_base:
                # The anthropic SDK names this base_url.
                kwargs["base_url"] = self._api_base
            self._client = anthropic.Anthropic(**kwargs)
        return self._client

    def complete(
        self,
        *,
        system: str,
        messages: list[Message],
        model: str,
        max_tokens: int,
        cache: bool = False,
    ) -> CompletionResult:
        system_param: Any = system
        if cache and system:
            system_param = [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}]
        request: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "timeout": self._timeout,
            "system": system_param,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
        }
        response = self._create(request)
        return CompletionResult(text=require_completion_text(_extract_text(response), provider="anthropic"))

    def _create(self, request: dict[str, Any]) -> Any:
        client = self._get_client()
        if self._temperature is None:
            return client.messages.create(**request)
        try:
            return client.messages.create(temperature=self._temperature, **request)
        except Exception as exc:
            if not _is_temperature_rejected(exc):
                raise
            # Drop it for this provider so later calls skip the rejected param, no wasted retry.
            self._temperature = None
            return client.messages.create(**request)


def _is_temperature_rejected(exc: Exception) -> bool:
    """True when the API refused the call only because this model does not accept the
    temperature param, the one error recovered from by dropping it. Matched on the
    message, not a model name list, so a new reasoning model needs no code change."""
    status = getattr(exc, "status_code", None)
    if status != 400 and "BadRequest" not in type(exc).__name__:
        return False
    return "temperature" in str(exc).lower()


def _extract_text(response: Any) -> str:
    content = getattr(response, "content", None)
    if not isinstance(content, list):
        return str(content or "")
    parts: list[str] = []
    for block in content:
        text = getattr(block, "text", None)
        if text is None and isinstance(block, dict):
            text = block.get("text")
        if text:
            parts.append(str(text))
    return "".join(parts)

"""OpenAIProvider: a provider backed by the OpenAI API, Chat Completions or Responses.

The default wire is Chat Completions, where the system prompt is the first chat message.
`wire_api="responses"` switches to the Responses API the GPT-5 reasoning models use, where
the system prompt is `instructions` and the turns are the `input`. A reasoning model
rejects a fixed temperature, so the Responses path sets none. `cache` is accepted but not
applied, OpenAI caches long prompts server-side with no request parameter to set. The
client is injectable so the mapping tests without the SDK or a key. This also serves any
OpenAI-compatible gateway through `api_base`.
"""

from __future__ import annotations

from typing import Any

from opfor.core.providers.base import CompletionResult, Message, Provider, require_completion_text


class OpenAIProvider(Provider):
    def __init__(self, *, api_key: str | None = None, api_base: str | None = None,
                 client: Any | None = None, wire_api: str = "chat", timeout: float = 240.0) -> None:
        self._api_key = api_key
        self._api_base = api_base
        self._client = client
        self._wire_api = wire_api
        # A per request deadline, so a hung or rate-limit-stalled call returns to the retry
        # layer to back off rather than holding the slot until a far longer ceiling.
        self._timeout = timeout

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                import openai
            except ImportError as exc:
                raise RuntimeError("the openai backend needs the openai SDK, install opfor[openai]") from exc
            kwargs: dict[str, Any] = {}
            if self._api_key:
                kwargs["api_key"] = self._api_key
            if self._api_base:
                # The openai SDK names this base_url.
                kwargs["base_url"] = self._api_base
            self._client = openai.OpenAI(**kwargs)
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
        if self._wire_api == "responses":
            return self._complete_responses(system=system, messages=messages, model=model,
                                            max_tokens=max_tokens)
        api_messages: list[dict] = []
        if system:
            api_messages.append({"role": "system", "content": system})
        api_messages += [{"role": m.role, "content": m.content} for m in messages]
        response = self._get_client().chat.completions.create(
            model=model,
            messages=api_messages,
            max_tokens=max_tokens,
            temperature=0,
            timeout=self._timeout,
        )
        return CompletionResult(text=require_completion_text(_choice_text(response), provider="openai"))

    def _complete_responses(
        self, *, system: str, messages: list[Message], model: str, max_tokens: int
    ) -> CompletionResult:
        """The Responses API path the GPT-5 reasoning models use. The budget covers reasoning
        plus output, so it is generous. A budget too small yields empty output, which reads
        as an unusable reply upstream and keeps the finding, never a silent wrong verdict."""
        user_input = "\n\n".join(m.content for m in messages)
        response = self._get_client().responses.create(
            model=model,
            instructions=system or None,
            input=user_input,
            max_output_tokens=max(max_tokens, 8000),
            timeout=self._timeout,
        )
        return CompletionResult(text=require_completion_text(getattr(response, "output_text", "") or "", provider="openai"))


def _choice_text(response: Any) -> str:
    """Text from the chat-completions response shape, a string or a list of content blocks."""
    choices = getattr(response, "choices", None) or []
    if not choices:
        return ""
    message = getattr(choices[0], "message", choices[0])
    content = getattr(message, "content", None)
    if content is None and isinstance(message, dict):
        content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, dict) and "text" in block:
                parts.append(str(block["text"]))
            elif isinstance(block, str):
                parts.append(block)
        return "".join(parts)
    return str(content or "")

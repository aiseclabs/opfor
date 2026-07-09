"""A provider that returns canned text instead of calling a model.

It drives the tests and any keyless dry run, so the judgment path runs with no API key
and deterministic output. It holds no parsing logic, it returns the text it was given
and records each call for inspection.
"""

from __future__ import annotations

from opfor.core.providers.base import CompletionResult, Message, Provider


class MockProvider(Provider):
    def __init__(self, *, responses: list[str] | None = None, default: str = "") -> None:
        self._responses = list(responses or [])
        self._default = default
        self.calls: list[dict] = []

    def complete(
        self,
        *,
        system: str,
        messages: list[Message],
        model: str,
        max_tokens: int,
        cache: bool = False,
    ) -> CompletionResult:
        self.calls.append({"system": system, "messages": messages, "model": model})
        text = self._responses.pop(0) if self._responses else self._default
        return CompletionResult(text=text)

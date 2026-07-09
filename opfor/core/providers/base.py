"""The provider contract and its typed input and output.

Deliberately minimal, one synchronous non-streaming `complete`. Streaming and tool
calling are left out until a concrete need appears, so the interface does not
over-commit early. `cache` is a portable hint, not a guarantee. Anthropic supports
prompt caching natively, a subprocess call cannot, so each provider maps the hint onto
its own implementation or ignores it.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Literal

Role = Literal["user", "assistant"]


@dataclass(frozen=True, kw_only=True)
class Message:
    role: Role
    content: str


@dataclass(frozen=True, kw_only=True)
class CompletionResult:
    text: str


class Provider(ABC):
    @abstractmethod
    def complete(
        self,
        *,
        system: str,
        messages: list[Message],
        model: str,
        max_tokens: int,
        cache: bool = False,
    ) -> CompletionResult:
        """Answer one prompt. A failed or blank call raises, it never returns empty text
        dressed as a clean result, invariant 5."""

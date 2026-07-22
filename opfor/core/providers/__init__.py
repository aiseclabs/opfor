"""The model provider layer, a generic kernel primitive any scenario may use.

A `Provider` is one synchronous call to a language model. Triage and an open-ended
planner reach for it when the next judgment is semantic rather than mechanical, so
attack knowledge stays prose a model reads, never a keyword list a rule hardcodes. The
layer names no scenario, the same way the rest of the kernel does not.

The default backend is the operator's Claude Code subscription through a headless
`claude -p`, so a run judges with no provider key. Setting a key in the environment
switches to a vendor API instead. `make_provider` reads that choice from the
environment, see `.env.example`.
"""

from __future__ import annotations

from opfor.core.providers.contract import CompletionResult, Message, Provider
from opfor.core.providers.factory import ProviderConfig, make_provider
from opfor.core.providers.mock import MockProvider

__all__ = [
    "CompletionResult",
    "Message",
    "MockProvider",
    "Provider",
    "ProviderConfig",
    "make_provider",
]

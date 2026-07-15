"""Build a provider from a name and the environment.

The default backend is the operator's Claude Code subscription through `claude -p`, so a
run judges with no provider key. `OPFOR_EXECUTOR` chooses the seat. `auto`, the default,
calls the vendor API when a key is reachable and otherwise runs on the subscription.
`api` always calls the API and requires a key. `subscription` always runs `claude -p`.

Every value is read from the environment once, in `ProviderConfig.from_env`, at the call
that builds a provider, never at import. So a long-lived process or a test that changes the
environment sees the change, and importing this module triggers no environment read.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping

from opfor.core.providers.anthropic import AnthropicProvider
from opfor.core.providers.base import Provider
from opfor.core.providers.claude_agent import ClaudeAgentProvider
from opfor.core.providers.openai import OpenAIProvider
from opfor.core.providers.retry import RetryProvider

PROVIDERS = ("anthropic", "openai")
# Only anthropic has a keyless subscription backend through `claude -p`, so it is the one
# provider `auto` can run without a key.
_KEYLESS_PROVIDERS = ("anthropic",)

# The vendor SDK reads this when no explicit key is passed, so a seat can authenticate an
# API call from the environment alone. Used to decide whether `auto` has a reachable key.
_SDK_KEY_ENV = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}


@dataclass(frozen=True, kw_only=True)
class ProviderConfig:
    """The provider settings a run reads from the environment. Built by `from_env` at the
    call that needs it, so no value is frozen at import and a changed environment is seen."""

    provider: str = "anthropic"
    model: str = "claude-opus-4-8"
    api_key: str | None = None
    api_base: str | None = None
    executor: str = "auto"
    wire_api: str = "chat"
    retries: int = 2
    timeout: float = 240.0
    triage_mode: str = "standard"

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "ProviderConfig":
        """Read the provider settings from the environment, `os.environ` by default. A test
        passes its own mapping to drive a backend without touching the process environment."""
        env = os.environ if env is None else env
        return cls(
            provider=env.get("OPFOR_PROVIDER", "anthropic"),
            model=env.get("OPFOR_MODEL", "claude-opus-4-8"),
            api_key=env.get("OPFOR_API_KEY"),
            api_base=env.get("OPFOR_API_BASE"),
            executor=env.get("OPFOR_EXECUTOR", "auto"),
            wire_api=env.get("OPFOR_WIRE_API", "chat"),
            retries=int(env.get("OPFOR_RETRIES", "2")),
            timeout=float(env.get("OPFOR_TIMEOUT", "240")),
            triage_mode=env.get("OPFOR_TRIAGE_MODE", "standard"),
        )


def default_model() -> str:
    """The model name a scenario uses when it names none, env-backed, read at the call."""
    return ProviderConfig.from_env().model


def triage_mode() -> str:
    """The triage judging mode, `standard` single-model by default or `adversarial`."""
    return ProviderConfig.from_env().triage_mode


def role_model(role: str, base: str) -> str:
    """The model for an adversarial role, its own `OPFOR_<ROLE>_MODEL` or the base model.

    A distinct model in the challenger or judge seat gives an uncorrelated second opinion,
    the point of the adversarial pass. With none set the role reuses the base model, which
    still gives an independent pass, just a correlated one."""
    return os.environ.get(f"OPFOR_{role.upper()}_MODEL") or base


def _has_key(provider: str, api_key: str | None) -> bool:
    """Whether a seat can authenticate an API call, an explicit key or the vendor SDK var."""
    if api_key:
        return True
    env = _SDK_KEY_ENV.get(provider)
    return bool(env and os.environ.get(env))


def make_provider(
    name: str | None = None,
    *,
    api_key: str | None = None,
    api_base: str | None = None,
    executor: str | None = None,
    wire_api: str | None = None,
    retries: int | None = None,
    timeout: float | None = None,
    config: ProviderConfig | None = None,
) -> Provider:
    """Build the provider the environment selects. A keyless `auto` or `subscription` seat
    runs the headless `claude -p` agent, otherwise the vendor API wrapped in retries. The
    config is read from the environment at this call unless one is passed."""
    config = config or ProviderConfig.from_env()
    name = name or config.provider
    api_key = api_key if api_key is not None else config.api_key
    api_base = api_base if api_base is not None else config.api_base
    executor = executor or config.executor
    wire_api = wire_api or config.wire_api
    retries = config.retries if retries is None else retries
    timeout = config.timeout if timeout is None else timeout

    if name not in PROVIDERS:
        raise RuntimeError(f"unknown provider {name!r}, known: {', '.join(PROVIDERS)}")

    keyless = name in _KEYLESS_PROVIDERS
    if executor == "subscription":
        if not keyless:
            raise RuntimeError(f"the {name} seat has no keyless subscription backend, "
                               "only anthropic does. set OPFOR_EXECUTOR=api with a key")
        return ClaudeAgentProvider(timeout=int(timeout))
    if executor == "auto" and not _has_key(name, api_key):
        if not keyless:
            raise RuntimeError(
                f"the {name} seat has no reachable API key and no keyless subscription "
                "backend. set OPFOR_API_KEY or OPFOR_EXECUTOR=api"
            )
        return ClaudeAgentProvider(timeout=int(timeout))
    if executor == "api" and not _has_key(name, api_key):
        raise RuntimeError(
            f"the {name} seat has no reachable API key and OPFOR_EXECUTOR=api requires one. "
            "set OPFOR_API_KEY, or OPFOR_EXECUTOR=subscription to run on the Claude Code "
            "subscription when the provider is anthropic"
        )

    if name == "openai":
        provider: Provider = OpenAIProvider(api_key=api_key, api_base=api_base,
                                            wire_api=wire_api, timeout=timeout)
    else:
        provider = AnthropicProvider(api_key=api_key, api_base=api_base, timeout=timeout)
    if retries > 0:
        provider = RetryProvider(provider, max_attempts=retries + 1, hard_timeout=timeout)
    return provider

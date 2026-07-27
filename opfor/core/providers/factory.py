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
# The runtime knobs that take one of a fixed set of values, so a typo is caught at config read
# rather than silently ignored. An unknown executor would otherwise fall through to a keyless API
# seat, a wrong result with no error. Triage policy is not here, it lives in `opfor.core.triage`.
EXECUTORS = ("auto", "api", "subscription")
WIRE_APIS = ("chat", "responses")
# Only anthropic has a keyless subscription backend through `claude -p`, so it is the one
# provider `auto` can run without a key.
_KEYLESS_PROVIDERS = ("anthropic",)


def _require_one_of(value: str, allowed: tuple[str, ...], label: str, var: str) -> None:
    """Fail loud when a setting is not one of its allowed values, naming the knob to set."""
    if value not in allowed:
        raise ValueError(
            f"{label} {value!r} is not supported, set {var} to one of {', '.join(allowed)}")


def _int_env(env: Mapping[str, str], var: str, default: str) -> int:
    """An integer read from the environment, failing loud and naming the variable when the
    value is not an integer, rather than the bare `invalid literal for int()` of a raw cast."""
    raw = env.get(var, default)
    try:
        return int(raw)
    except (TypeError, ValueError):
        raise ValueError(f"{var}={raw!r} is not an integer") from None


def _float_env(env: Mapping[str, str], var: str, default: str) -> float:
    """A float read from the environment, failing loud and naming the variable when the value
    is not a number."""
    raw = env.get(var, default)
    try:
        return float(raw)
    except (TypeError, ValueError):
        raise ValueError(f"{var}={raw!r} is not a number") from None


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

    def __post_init__(self) -> None:
        """Validate every setting at config read, so a bad value fails here with a clear
        reason rather than late inside a provider call or, worse, silently ignored. This
        guards every construction path, the environment read and a direct config alike."""
        _require_one_of(self.provider, PROVIDERS, "provider", "OPFOR_PROVIDER")
        _require_one_of(self.executor, EXECUTORS, "executor", "OPFOR_EXECUTOR")
        _require_one_of(self.wire_api, WIRE_APIS, "wire API", "OPFOR_WIRE_API")
        if self.retries < 0:
            raise ValueError(
                f"retries must be zero or more, set OPFOR_RETRIES to a non-negative integer, "
                f"got {self.retries}")
        if self.timeout <= 0:
            raise ValueError(
                f"timeout must be greater than zero, set OPFOR_TIMEOUT to a positive number, "
                f"got {self.timeout}")

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "ProviderConfig":
        """Read the provider settings from the environment, `os.environ` by default. A test
        passes its own mapping to drive a backend without touching the process environment.
        Every value is validated in `__post_init__`, so a bad enum or a non-numeric timeout
        fails loud here rather than late inside a provider call."""
        env = os.environ if env is None else env
        return cls(
            provider=env.get("OPFOR_PROVIDER", "anthropic"),
            model=env.get("OPFOR_MODEL", "claude-opus-4-8"),
            api_key=env.get("OPFOR_API_KEY"),
            api_base=env.get("OPFOR_API_BASE"),
            executor=env.get("OPFOR_EXECUTOR", "auto"),
            wire_api=env.get("OPFOR_WIRE_API", "chat"),
            retries=_int_env(env, "OPFOR_RETRIES", "2"),
            timeout=_float_env(env, "OPFOR_TIMEOUT", "240"),
        )


def default_model() -> str:
    """The model name a scenario uses when it names none, env-backed, read at the call."""
    return ProviderConfig.from_env().model


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

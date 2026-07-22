"""The headless `claude -p` provider, the keyless subscription backend.

A subscription seat runs a headless Claude Code agent through `claude -p` instead of
calling a vendor API, so it judges on the operator's Claude Code access with no provider
key or proxy limit. The prompt is already whole in the message, so the agent takes no
file tools, and `model` is advisory since the subscription picks the model.

The exact `claude` invocation varies by version, so the binary and its extra args are
configurable through the constructor or `OPFOR_CLAUDE_BIN` and `OPFOR_CLAUDE_ARGS`. The
prompt is fed on stdin so a large mandate does not hit the argv limit. The subprocess
call goes through an injected runner, so this tests with no real `claude`. This module
imports only the standard library and `providers.contract`, so it stays a leaf.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import time
from typing import Callable

from opfor.core.providers.contract import CompletionResult, Message, Provider, require_completion_text

_OUTPUT_ARGS = ("--output-format", "json")
# The nested `claude -p` must authenticate with the operator's subscription, not an API
# key opfor might carry for its own provider call. An inherited key or base URL, stale or
# pointed at a proxy, makes the nested agent 401 instead of riding the subscription, so
# they are scrubbed from its environment.
_SCRUBBED_AUTH_ENV = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL")

Runner = Callable[..., str]


def _subscription_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k not in _SCRUBBED_AUTH_ENV}


def _envelope_error(stdout: str) -> str | None:
    """An error reported inside a `--output-format json` envelope, or None.

    A rate-limited or failed `claude -p` can still exit 0 while the envelope carries
    `is_error` or a non-success subtype. Treating that as success silently turns a failed
    call into an empty clean result, the exact thing invariant 5 forbids, so the runner
    detects it and raises."""
    try:
        env = json.loads(stdout.strip())
    except json.JSONDecodeError:
        return None
    if not isinstance(env, dict):
        return None
    if env.get("is_error") or env.get("api_error_status") or env.get("subtype", "success") != "success":
        return str(env.get("api_error_status") or env.get("subtype") or "is_error")
    return None


def _default_runner(prompt: str, *, cwd: str, claude_bin: str, args: tuple[str, ...], timeout: int) -> str:
    """Run `claude -p` headless with the prompt on stdin, return stdout, raise on error."""
    proc = subprocess.run(
        [claude_bin, "-p", *args],
        input=prompt, cwd=cwd or None, env=_subscription_env(),
        capture_output=True, text=True, timeout=timeout,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"claude exited {proc.returncode}: {proc.stderr.strip()[:300]}")
    err = _envelope_error(proc.stdout)
    if err:
        raise RuntimeError(f"claude reported an error, {err}: {proc.stdout.strip()[:200]}")
    return proc.stdout


def _result_text(stdout: str) -> str:
    """Pull the assistant text out of `--output-format json`, or pass plain text through."""
    s = stdout.strip()
    try:
        env = json.loads(s)
        if isinstance(env, dict) and "result" in env:
            return str(env["result"])
    except json.JSONDecodeError:
        pass
    return s


def _fold_prompt(system: str, messages: list[Message]) -> str:
    """Fold the system text and messages into one stdin prompt, since `claude -p` has no
    separate system channel. The system text leads so a "respond with one JSON object"
    instruction still governs the reply. A role label is added only when more than one
    message would be ambiguous, so a single-message call stays verbatim."""
    parts: list[str] = []
    if system:
        parts.append(system)
    multi = len(messages) > 1
    for m in messages:
        parts.append(f"[{m.role}] {m.content}" if multi else m.content)
    return "\n\n".join(parts)


class ClaudeAgentProvider(Provider):
    """A provider that answers through a headless `claude -p` agent on the operator's
    Claude Code subscription instead of a vendor API, so a run judges with no provider
    key. `cache` does not apply to a subprocess call. A blank or error-enveloped reply
    raises through `_ask`, it never returns as an empty clean result."""

    def __init__(
        self,
        *,
        claude_bin: str | None = None,
        args: tuple[str, ...] | None = None,
        cwd: str = "",
        timeout: int = 900,
        retries: int = 2,
        backoff: float = 10.0,
        runner: Runner | None = None,
    ) -> None:
        self._bin = claude_bin or os.environ.get("OPFOR_CLAUDE_BIN", "claude")
        env_args = os.environ.get("OPFOR_CLAUDE_ARGS")
        extra = tuple(shlex.split(env_args)) if env_args else (tuple(args) if args else ())
        self._args = (*_OUTPUT_ARGS, *extra)
        self._cwd = cwd
        self._timeout = timeout
        self._retries = retries
        self._backoff = backoff
        # An injected runner is the test seam, otherwise the real subprocess call.
        self._runner = runner or _default_runner

    def complete(
        self,
        *,
        system: str,
        messages: list[Message],
        model: str,
        max_tokens: int,
        cache: bool = False,
    ) -> CompletionResult:
        text = _result_text(self._ask(_fold_prompt(system, messages)))
        return CompletionResult(text=require_completion_text(text, provider="claude"))

    def _ask(self, prompt: str) -> str:
        """Run the agent, retrying with backoff since a rate limit is usually transient.
        Raises the last error if every attempt fails, so the caller counts it."""
        last: Exception | None = None
        for attempt in range(self._retries + 1):
            try:
                return self._runner(
                    prompt, cwd=self._cwd, claude_bin=self._bin, args=self._args, timeout=self._timeout)
            except Exception as exc:
                last = exc
                if attempt < self._retries and self._backoff:
                    time.sleep(self._backoff * (attempt + 1))
        assert last is not None
        raise last

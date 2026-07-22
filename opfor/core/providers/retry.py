"""A provider wrapper that retries a transient failure and bounds each call.

A rate limit or a network blip is usually transient, so one retry recovers it. The
wrapper enforces a hard timeout with a daemon thread as well, for the case the wrapped
SDK timeout cannot cover, such as a proxy that holds the connection open. When every
attempt fails it raises the last error, so a failed call is never dressed as clean,
invariant 5.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import Future

from opfor.core.providers.contract import CompletionResult, Message, Provider


class RetryProvider(Provider):
    def __init__(self, inner: Provider, *, max_attempts: int = 3, hard_timeout: float = 240.0,
                 backoff: float = 2.0) -> None:
        self._inner = inner
        self._max_attempts = max(1, max_attempts)
        self._hard_timeout = hard_timeout
        self._backoff = backoff

    def complete(
        self,
        *,
        system: str,
        messages: list[Message],
        model: str,
        max_tokens: int,
        cache: bool = False,
    ) -> CompletionResult:
        last: Exception | None = None
        for attempt in range(self._max_attempts):
            try:
                return self._bounded(
                    system=system, messages=messages, model=model, max_tokens=max_tokens, cache=cache)
            except Exception as exc:
                last = exc
                if attempt < self._max_attempts - 1 and self._backoff:
                    time.sleep(self._backoff * (attempt + 1))
        assert last is not None
        raise last

    def _bounded(self, **kwargs) -> CompletionResult:
        """Run one call under a hard deadline. The worker is a daemon thread, so a call
        that never returns does not block interpreter exit, and the deadline raises rather
        than letting a stalled call hold the slot forever."""
        fut: Future = Future()

        def work() -> None:
            try:
                fut.set_result(self._inner.complete(**kwargs))
            except Exception as exc:
                fut.set_exception(exc)

        threading.Thread(target=work, daemon=True).start()
        return fut.result(timeout=self._hard_timeout)

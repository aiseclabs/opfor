"""Whether an error is a transient transport blip worth retrying, rather than a real failure.

A timeout or a dropped connection is momentary: the same work often succeeds moments later. A
refusal, a parse error, or a logic error is not, retrying only wastes time and hides the real
result. The engine retries the transient kind and fails loud on the rest, so this is the one place
that decision is made. It is generic, it names only the standard-library transport exceptions any
source raises, no protocol specifics. A scenario that speaks a protocol with its own retry-me
signal, an HTTP 429 or 503, classifies that in its own source layer and composes it with this.
"""

from __future__ import annotations

import socket


def is_transient(exc: BaseException) -> bool:
    """True when the error is a momentary transport condition a retry can recover, a timeout or a
    dropped connection, judged only on the standard-library exception type, no protocol knowledge."""
    return isinstance(exc, (TimeoutError, socket.timeout, ConnectionError))

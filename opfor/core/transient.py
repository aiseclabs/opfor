"""Whether an error is a transient network blip worth retrying, rather than a real failure.

A rate limit, a gateway error, a timeout, or a dropped connection is momentary: the same request
often succeeds moments later. A refusal, a not-found, a parse error is not, retrying only wastes
time and hides the real result. The engine retries the transient kind and fails loud on the rest,
so this classifier is the one place that decision is made, generic over any network source.
"""

from __future__ import annotations

import socket
import urllib.error

# HTTP status codes that are a server or a rate limiter asking to try again, not a real no.
_TRANSIENT_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})


def is_transient(exc: BaseException) -> bool:
    """True when the error is a momentary network condition a retry can recover."""
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code in _TRANSIENT_STATUS
    if isinstance(exc, urllib.error.URLError):
        # URLError wraps the underlying socket error, a timeout or a refused or reset connection.
        return is_transient(exc.reason) if isinstance(exc.reason, BaseException) else True
    if isinstance(exc, (TimeoutError, socket.timeout, ConnectionError)):
        return True
    return False

"""Capability failure, coverage, and tolerance helpers shared across the domain capabilities.

A network error becomes a `Failed` marked transient when retryable, a per-item scan that skipped
items records a coverage gap rather than passing a partial surface off as clean, and a candidate
source that raises is tolerated so a union survives one bad member. All three keep a failure loud
or bounded rather than silent, invariant 5.
"""

from __future__ import annotations

from opfor.core import Failed, is_transient
from opfor.scenarios.attacksurface.assets.domain.types import CoverageGap

_MAX_GAP_REASONS = 5


def net_failed(prefix: str, exc: Exception) -> Failed:
    """A `Failed` for a network error, marked transient when the error is a retryable blip.

    So the engine retries a rate limit, a gateway error, or a timeout rather than dropping the
    whole capability result, while a real error still fails terminal and loud, invariant 5.
    """
    return Failed(reason=f"{prefix} {type(exc).__name__}: {exc}", transient=is_transient(exc))


def _coverage_gap(scan: str, host: str, attempted: int, skipped: list[str]) -> CoverageGap | None:
    """A coverage gap payload when a per-item scan skipped items on errors, else None. So a
    scan that dropped items keeps the drop loud rather than passing a partial surface off as
    a clean negative, invariant 5. The reasons are a bounded sample so the fact stays small."""
    if not skipped:
        return None
    return CoverageGap(scan=scan, host=host, attempted=attempted, failed=len(skipped),
                       reasons=tuple(skipped[:_MAX_GAP_REASONS]))


def _safe(thunk):
    """Run a candidate source, returning None on any error so the union tolerates it."""
    try:
        return thunk()
    except Exception:
        return None

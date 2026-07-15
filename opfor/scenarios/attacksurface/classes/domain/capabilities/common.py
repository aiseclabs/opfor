"""Shared module-level helpers and constants for the domain capabilities."""

from __future__ import annotations

import re

from opfor.scenarios.attacksurface.classes.domain.types import CoverageGap

_LINK = re.compile(r'(?:href|src)\s*=\s*["\']([^"\'#?]+)', re.IGNORECASE)
# Same-host bundles checked for a source map per host, bounded so a bundle-heavy app stays
# a small number of extra reads.
_MAX_SOURCE_MAPS = 12

_MAX_GAP_REASONS = 5


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


def _is_static_asset(path: str, suffixes, prefixes) -> bool:
    """Whether a path is a static asset, given the suffix and prefix lists the planner
    handed in from knowledge, so the capability itself reads no knowledge file."""
    lowered = path.lower().split("?")[0]
    return lowered.endswith(tuple(suffixes)) or lowered.startswith(tuple(prefixes))


def _distinct(result: dict, baseline: dict) -> bool:
    """Whether a response is a real endpoint rather than the host's catch-all.

    When the catch-all is a positive page, a single-page app that answers 200 for every
    path, an endpoint counts only if it differs in status, in content type, or clearly in
    body size. When the catch-all is a uniform non-2xx, a blanket login redirect or a
    front-proxy 403, an endpoint that answers the same status but redirects to a different
    location is still real, so a differing location counts as distinct.
    """
    base_status = baseline.get("status")
    if base_status is None:
        return True
    if result.get("status") != base_status:
        return True
    if not (200 <= int(base_status) < 300):
        # a uniform non-2xx catch-all still hides an endpoint that redirects elsewhere, such
        # as /admin answering 302 to /admin/dashboard behind a blanket 302 to /login
        location = result.get("location")
        return bool(location and location != baseline.get("location"))
    if _ct_family(result.get("content_type", "")) != _ct_family(baseline.get("content_type", "")):
        return True
    return abs(len(result.get("body", "")) - len(baseline.get("body", ""))) > 128


def _ct_family(content_type: str) -> str:
    return (content_type or "").split(";")[0].strip().lower()


def _home_paths(body: str, *, limit: int = 20) -> list[str]:
    """Same-origin absolute paths linked from a home page body, deduped and capped."""
    out: list[str] = []
    for href in _LINK.findall(body or ""):
        if href.startswith("/") and not href.startswith("//") and href not in out:
            out.append(href)
        if len(out) >= limit:
            break
    return out

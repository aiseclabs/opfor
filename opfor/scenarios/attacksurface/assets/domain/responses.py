"""Endpoint response comparison helpers shared across the domain capabilities.

They tell a real endpoint from a host's catch-all, a single-page app that answers 200 for every
path or a blanket login redirect, filter static assets out of the interface surface, and read the
same-origin links a home page carries. Pure functions over an already-fetched response, so a
capability compares what it probed without reading knowledge.
"""

from __future__ import annotations

import re

_LINK = re.compile(r'(?:href|src)\s*=\s*["\']([^"\'#?]+)', re.IGNORECASE)
# Same-host bundles checked for a source map per host, bounded so a bundle-heavy app stays
# a small number of extra reads.
_MAX_SOURCE_MAPS = 12


def _is_static_asset(path: str, suffixes, prefixes) -> bool:
    """Whether a path is a static asset, given the suffix and prefix lists the planner
    handed in from knowledge, so the capability itself reads no knowledge file."""
    lowered = path.lower().split("?")[0]
    return lowered.endswith(tuple(suffixes)) or lowered.startswith(tuple(prefixes))


def _baseline(fetch, paths, name, addresses) -> dict:
    """A host's answer to paths that do not exist, its catch-all signature, so `_distinct` can
    tell a real endpoint from a blanket 200 or a uniform redirect. The first path that answers
    with any status wins, and an empty signature is returned when none does. The caller injects
    its own fetch and its own unlikely paths, so the probe reads the target the caller scopes."""
    for path in paths:
        try:
            result = fetch(name, addresses, path)
        except Exception:
            continue
        if result.get("status") is not None:
            return result
    return {"status": None, "content_type": "", "body": ""}


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
        # as /admin answering 302 to /admin/dashboard behind a blanket 302 to /login. The
        # query is stripped before comparing, since a login wall that echoes the requested
        # path in a next parameter gives every path a different raw location and would
        # otherwise make every probe look distinct.
        location = _redirect_target(result.get("location"))
        return bool(location and location != _redirect_target(baseline.get("location")))
    if _ct_family(result.get("content_type", "")) != _ct_family(baseline.get("content_type", "")):
        return True
    return abs(len(result.get("body", "")) - len(baseline.get("body", ""))) > 128


def _redirect_target(location) -> str:
    """A redirect Location reduced to its path, dropping the query and fragment, so a login
    wall that echoes the requested path in a next parameter is recognized as one catch-all
    rather than a distinct target per path."""
    return str(location or "").split("?")[0].split("#")[0]


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

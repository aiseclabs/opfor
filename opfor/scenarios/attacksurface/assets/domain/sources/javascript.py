"""JavaScript URL, source map, and secret extraction for the domain class, apart from the network
so a test drives each one."""

from __future__ import annotations

import re

from opfor.scenarios.attacksurface.assets.domain.sources.parsers import same_host_path

_SCRIPT_SRC = re.compile(r'<script[^>]+src\s*=\s*["\']([^"\']+)', re.IGNORECASE)
_JS_PATH = re.compile(r"""["'`](/[A-Za-z0-9_.\-/]{1,160})["'`]""")
QUOTED_URL = re.compile(r"""["'`](https?://[A-Za-z0-9.\-]+(?::\d+)?(?:/[A-Za-z0-9_.\-/]{0,200})?)["'`]""")

# A ceiling on the path-like and url-like strings read out of one script body, so a hostile
# bundle packing hundreds of thousands of distinct quoted paths into the document byte limit
# cannot tie a worker thread or grow an unbounded candidate list. Far above the downstream
# probe cap, so a real bundle is never truncated and no probed path is lost to this.
_MAX_JS_STRINGS = 2000


def script_sources(body: str, host: str) -> list[str]:
    """Same-host JavaScript URLs a page loads, as paths, deduped in document order.

    A single-page app hardcodes its API routes in these bundles, so they are the first
    step to reading the app's own interface surface rather than guessing it.
    """
    out: list[str] = []
    seen: set[str] = set()
    for m in _SCRIPT_SRC.finditer(body or ""):
        src = m.group(1)
        path = same_host_path(src, host)
        if path and path.split("?")[0].lower().endswith(".js") and path not in seen:
            seen.add(path)
            out.append(path)
            if len(out) >= _MAX_JS_STRINGS:
                break
    return out


def paths_in_javascript(text: str) -> list[str]:
    """Path-like strings from a JavaScript body, deduped in appearance order.

    A bundle names the API routes it calls, so this reads them out. It is noisy by nature,
    a string that looks like a path is not always one, so the caller probes each to confirm
    rather than trusting it. Dedup is set-backed and the count is capped, so a large or
    hostile bundle is read out in linear time rather than quadratic.
    """
    out: list[str] = []
    seen: set[str] = set()
    # finditer with an early break, not findall, so the cap bounds the work and peak memory, not
    # only the stored output, on a hostile bundle packed with quoted paths.
    for m in _JS_PATH.finditer(text or ""):
        path = m.group(1).split("?")[0]
        if path.startswith("//") or len(path) < 2 or path in seen:
            continue
        # A path with no letter is a version or an index fragment such as /1 or /0/0, not a
        # route, so it is dropped before it becomes a wasted probe.
        if not any(c.isalpha() for c in path):
            continue
        seen.add(path)
        out.append(path)
        if len(out) >= _MAX_JS_STRINGS:
            break
    return out


def urls_in_javascript(text: str) -> list[str]:
    """Absolute http urls from a JavaScript body, deduped in appearance order.

    A single-page app names the API it calls on a sibling host by full url, so these are
    how a cross-host interface surface is read out rather than missed. Dedup is set-backed
    and the count is capped, so a large or hostile bundle is read out in linear time.
    """
    out: list[str] = []
    seen: set[str] = set()
    for m in QUOTED_URL.finditer(text or ""):
        match = m.group(1)
        if match in seen:
            continue
        seen.add(match)
        out.append(match)
        if len(out) >= _MAX_JS_STRINGS:
            break
    return out

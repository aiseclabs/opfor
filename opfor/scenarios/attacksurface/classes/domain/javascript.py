"""JavaScript URL, source map, and secret extraction for the domain class, apart from the network so a test drives each one."""

from __future__ import annotations

import json
import re

from opfor.scenarios.attacksurface.classes.domain.parsers import same_host_path

_SCRIPT_SRC = re.compile(r'<script[^>]+src\s*=\s*["\']([^"\']+)', re.IGNORECASE)
_JS_PATH = re.compile(r"""["'`](/[A-Za-z0-9_.\-/]{1,160})["'`]""")
_JS_URL = re.compile(r"""["'`](https?://[A-Za-z0-9.\-]+(?:/[A-Za-z0-9_.\-/]{0,200})?)["'`]""")

_MAX_SECRET_MATCHES = 20


def script_sources(body: str, host: str) -> list[str]:
    """Same-host JavaScript URLs a page loads, as paths, deduped in document order.

    A single-page app hardcodes its API routes in these bundles, so they are the first
    step to reading the app's own interface surface rather than guessing it.
    """
    out: list[str] = []
    for src in _SCRIPT_SRC.findall(body or ""):
        path = same_host_path(src, host)
        if path and path.split("?")[0].lower().endswith(".js") and path not in out:
            out.append(path)
    return out


def paths_in_javascript(text: str) -> list[str]:
    """Path-like strings from a JavaScript body, deduped in appearance order.

    A bundle names the API routes it calls, so this reads them out. It is noisy by nature,
    a string that looks like a path is not always one, so the caller probes each to confirm
    rather than trusting it.
    """
    out: list[str] = []
    for match in _JS_PATH.findall(text or ""):
        path = match.split("?")[0]
        if path.startswith("//") or len(path) < 2 or path in out:
            continue
        # A path with no letter is a version or an index fragment such as /1 or /0/0, not a
        # route, so it is dropped before it becomes a wasted probe.
        if not any(c.isalpha() for c in path):
            continue
        out.append(path)
    return out


def urls_in_javascript(text: str) -> list[str]:
    """Absolute http urls from a JavaScript body, deduped in appearance order.

    A single-page app names the API it calls on a sibling host by full url, so these are
    how a cross-host interface surface is read out rather than missed.
    """
    out: list[str] = []
    for match in _JS_URL.findall(text or ""):
        if match not in out:
            out.append(match)
    return out


def source_map_from_text(text: str) -> dict | None:
    """Whether a body is a JavaScript source map, and what it leaks, parsed apart from the
    fetch so a test drives it without a network call.

    Returns None when the body is not a source map. Otherwise returns the count of original
    sources, whether the original source is inlined in `sourcesContent`, and a few of the
    source paths as evidence. A large map may arrive truncated, so it falls back to a
    substring check when the JSON does not parse, since a truncated map is still a leak.
    """
    if not text:
        return None
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        data = None
    if isinstance(data, dict) and "version" in data and "sources" in data:
        sources = [str(s) for s in (data.get("sources") or [])]
        content = data.get("sourcesContent") or []
        return {"sources_count": len(sources),
                "has_sources_content": any(bool(c) for c in content),
                "sample_sources": tuple(sources[:5])}
    low = text.lower()
    if '"version"' in low and '"sources"' in low:
        return {"sources_count": low.count('"../') + low.count('webpack://'),
                "has_sources_content": '"sourcescontent"' in low,
                "sample_sources": ()}
    return None


def _redact(value: str) -> str:
    """A secret shown as a short prefix and its length, never in full, so the report and the
    log never carry the value itself."""
    value = value.strip()
    head = value[:6]
    return f"{head}...({len(value)} chars)"


def secrets_in_text(text: str, patterns) -> list[dict]:
    """Secret-like strings a set of patterns match in a body, redacted, parsed apart from
    the fetch so a test drives it without a network call.

    Each pattern is a dict with an id, a regex, and a note. Every distinct match is reported,
    deduped by redacted sample, so a bundle holding several keys of one shape surfaces all of
    them rather than only the first, bounded by a cap. A malformed regex is not swallowed
    here, patterns are validated loudly at load, so a bad one fails the run rather than
    silently disabling a whole secret class. Whether a match is live is triage's judgment.
    """
    out: list[dict] = []
    body = text or ""
    seen: set[tuple[str, str]] = set()
    for pattern in patterns or []:
        regex = str(pattern.get("regex", ""))
        if not regex:
            continue
        pid = str(pattern.get("id", ""))
        for match in re.finditer(regex, body):
            sample = _redact(match.group(0))
            key = (pid, sample)
            if key in seen:
                continue
            seen.add(key)
            out.append({"pattern": pid, "note": str(pattern.get("note", "")), "sample": sample})
            if len(out) >= _MAX_SECRET_MATCHES:
                return out
    return out

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


# The source map a bundle points a debugger to, at most a couple per script since only the
# first that names a tracked package is read. A map is JSON, and its `sources` array carries
# the on-disk path of each original file, which under a pnpm layout embeds the package version.
_SOURCEMAP_URL = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*([^\s'\"]+)", re.IGNORECASE)
_MAX_SOURCEMAPS = 2


def versions_in_script(body: str, patterns: dict) -> dict:
    """The framework versions a bundle's own content declares, one per framework whose anchored
    pattern hits. Each pattern is library-specific, a version literal glued to a token only that
    library emits such as React's `reconcilerVersion` or Vue's banner, so a match is a ground
    truth the code shipped, not a bare number guessed from anywhere in the file."""
    out: dict = {}
    for name, pattern in patterns.items():
        if pattern is None:
            continue
        match = pattern.search(body or "")
        if match:
            out[name] = match.group(1)
    return out


def sourcemap_targets(body: str, host: str, base_path: str = "") -> list[str]:
    """The same-host source map paths a script points to, deduped in order and capped.

    Read only when a bundle prints no version literal, and only for a same-host map, so a
    cross-origin map is never chased and a data-uri inline map is skipped. A bare relative
    reference, the common form a bundler emits, is resolved against the script's own directory in
    `base_path`, an absolute path is kept, and a full url is taken only when it names the host.
    Fetching a public static asset a page already links stays the recon tier of reading the bundle.
    """
    from posixpath import dirname, join, normpath

    out: list[str] = []
    seen: set[str] = set()
    for m in _SOURCEMAP_URL.finditer(body or ""):
        ref = m.group(1).strip().split("#")[0].split("?")[0]
        if not ref or ref.startswith("data:"):
            continue
        if ref.startswith(("http://", "https://")) or ref.startswith("/"):
            path = same_host_path(ref, host)
        else:
            path = normpath(join(dirname(base_path or "/"), ref))
        if path and path not in seen:
            seen.add(path)
            out.append(path)
            if len(out) >= _MAX_SOURCEMAPS:
                break
    return out


def versions_in_sourcemap(text: str, npm_by_name: dict) -> dict:
    """The framework versions a source map's `sources` paths embed, one per tracked package found.

    A pnpm layout writes each dependency under `.../<package>@<version>/...`, so the version rides
    in the original-file path the map records. This reads it only where a semver is glued to a
    tracked package name, so a flat npm layout, which carries no version in the path, yields
    nothing rather than a wrong number. The map body is bounded by the document fetch cap.
    """
    import json

    out: dict = {}
    try:
        sources = json.loads(text or "").get("sources") or []
    except (ValueError, AttributeError):
        return out
    joined = "\n".join(str(s) for s in sources)
    for name, package in npm_by_name.items():
        if not package:
            continue
        match = re.search(re.escape(package.lower()) + r"@([0-9]+\.[0-9]+\.[0-9]+)", joined.lower())
        if match:
            out[name] = match.group(1)
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

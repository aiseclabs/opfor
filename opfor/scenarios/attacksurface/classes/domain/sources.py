"""Domain-class sources facade, re-exporting from http, passive, parsers, and scanners.

The transport lives in `http`, the passive OSINT source clients in `passive`, the body and
document parsers in `parsers`, and the content scanners in `scanners`. This module gathers
their public names in one place so a caller keeps a single import, and it holds the small
JavaScript path readers and the Wayback source that sit between a fetch and a parse.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request

from opfor.scenarios.attacksurface.classes.domain.http import (
    _TIMEOUT,
    _UA,
    _signal_headers,
    fetch_document,
    fetch_public_url,
    fetch_url,
    graphql_introspect,
    http_probe,
    public_addresses,
    resolve_host,
)
from opfor.scenarios.attacksurface.classes.domain.passive import (
    Enumeration,
    cert_sibling_roots,
    certspotter_subdomains,
    cves_from_nvd,
    dnsdumpster_subdomains,
    hosts_from_file,
    nvd_cves,
    otx_subdomains,
    reverse_whois,
    roots_from_file,
    roots_from_reverse_whois,
    sibling_roots_from_issuances,
    subdomains,
    subdomains_from_dnsdumpster,
    subdomains_from_otx,
    subdomains_from_vt,
    virustotal_subdomains,
)
from opfor.scenarios.attacksurface.classes.domain.parsers import (
    _JS_PATH,
    _JS_URL,
    info_from_openapi,
    operations_from_introspection,
    paths_from_openapi,
    robots_entries,
    same_host_path,
    script_sources,
    sitemap_paths,
    source_map_from_text,
    split_operation,
)
from opfor.scenarios.attacksurface.classes.domain.scanners import (
    backup_candidates,
    bucket_listable,
    cloud_bucket_from_url,
    cloud_refs_in_text,
    secrets_in_text,
)


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


def wayback_paths(host: str) -> set[str]:
    """Historical url paths for a host from the Wayback Machine CDX index, a passive read.

    It names paths that once existed without touching the target. It is one source in a
    union, so the caller tolerates its failure rather than letting it block the others.
    """
    url = (f"http://web.archive.org/cdx/search/cdx?url={urllib.parse.quote(host)}/*"
           "&output=json&fl=original&collapse=urlkey&limit=2000")
    request = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=_TIMEOUT) as resp:
        rows = json.loads(resp.read().decode("utf-8", "replace"))
    out: set[str] = set()
    for row in rows[1:] if rows and isinstance(rows[0], list) else []:
        path = same_host_path(str(row[0]), host)
        if path:
            out.add(path)
    return out

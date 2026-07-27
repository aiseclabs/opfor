"""Domain-class passive enumeration: subdomains and paths from public indexes.

All standard library, no installed tool. Certificate transparency, passive DNS, and the Wayback
archive name hosts and paths from public sources without touching the target, an osint read. Each
source is an injected seam, so a test drives the scenario with fixtures, and each is best effort so
one dead source does not blind the rest. The HTTP transport these lean on lives in `http`, imported
rather than duplicated.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from opfor.scenarios.attacksurface.assets.domain.sources import keys
from opfor.scenarios.attacksurface.hostnames import host_from_record, looks_like_host
from opfor.scenarios.attacksurface.assets.domain.sources.dns import _JSON_LIMIT, _TIMEOUT, _UA
from opfor.scenarios.attacksurface.assets.domain.sources.parsers import same_host_path


# --- certificate transparency: subdomains without touching the target -------


# The certspotter free endpoint returns a bounded page, so a walk follows the `after`
# cursor. With a key the quota allows a full walk. Without one the free quota is tiny, so
# paging hard would exhaust it and self-throttle, so a keyless walk stays to a couple of
# pages, still the most recent certificates, and leans on the other sources for the rest.
_CERTSPOTTER_PAGES = 30
_CERTSPOTTER_PAGES_KEYLESS = 2


class Enumeration(set):
    """A set of discovered subdomains that also records whether a source truncated. A page
    cap that stops short of the full log leaves subdomains unfetched, so the fact is carried
    up rather than passing as a complete result, invariant 5."""

    truncated = False


def subdomains(domain: str) -> Enumeration:
    """Passive subdomains of a domain, the union of certificate transparency, VirusTotal,
    and OTX.

    certspotter reads public certificate logs, VirusTotal and OTX join when their key is set.
    VirusTotal is a reliable passive source where a keyless source is throttled by shared
    address, and OTX reads passive DNS, the hostnames a resolver answered for, which surfaces
    live hosts a wildcard certificate hides from the logs.
    All are public reads that never touch the target. Each source is best effort, an
    individual failure is tolerated so one dead source does not blind the rest, and only
    when every source fails is the failure raised, so an empty result means no records
    rather than a dead source. crt.sh once joined as a second window on the same logs, but
    it answered 502 or timed out far more often than it answered, so it was dropped, its
    data class is already covered by certspotter. A source that hit its page cap marks the
    union truncated, so a bounded fetch is reported as a blind spot rather than a full set.
    """
    # Two keyless windows: certificate logs name cert-holding hosts, the Wayback archive names
    # crawled or linked hosts, so together they cover a host one alone misses, such as one a
    # wildcard certificate hides. Each is tolerated if it fails, the union raises only when every
    # source fails. The keyed passive-DNS sources below add a third window when configured.
    sources = [certspotter_subdomains, wayback_subdomains]
    if keys.virustotal_key():
        sources.append(virustotal_subdomains)
    if keys.otx_key():
        sources.append(otx_subdomains)
    names: set[str] = set()
    truncated = False
    errors: list[str] = []
    for source in sources:
        try:
            result = source(domain)
            names |= result
            truncated = truncated or getattr(result, "truncated", False)
        except Exception as exc:
            errors.append(f"{source.__name__}: {exc}")
    if not names and len(errors) == len(sources):
        raise RuntimeError("all passive subdomain sources failed: " + ", ".join(errors))
    # Passive DNS sources return DNS control-record names too, `_dmarc`, `_domainkey`, an ACME
    # `_acme-challenge` label. These are not hosts, so `host_from_record` unwraps a leading
    # validation label to the host it protects and drops a pure control record, the same filter
    # the DNS-export path applies, so a `_dmarc` name is never admitted as a probeable subdomain.
    hosts = {host for name in names if (host := host_from_record(name)) is not None}
    union = Enumeration(hosts)
    union.truncated = truncated
    # A source that failed while others answered is a blind spot, so the errors ride the
    # union and the capability surfaces them, rather than a partial set passing as the full
    # subdomain surface, invariant 5.
    union.source_errors = tuple(errors)
    union.source_count = len(sources)
    return union


def certspotter_subdomains(domain: str) -> Enumeration:
    """Subdomains of a domain seen in certificate transparency, via certspotter, paged.

    The free endpoint returns one bounded page, so the walk follows the `after` cursor
    across pages rather than stopping at the first, which multiplies recall many times over
    on a large log. See `_certspotter_paged` for the page cap and the keyless 429 fallback
    every certspotter reader shares. A walk that spends its whole page budget with the log
    still yielding leaves certificates unread, so the result is flagged truncated rather than
    passing as complete, invariant 5.
    """
    names: set[str] = set()
    issuances, truncated = _certspotter_paged(domain)
    for issuance in issuances:
        for raw in issuance.get("dns_names", []):
            # a wildcard such as *.dev.example.com is kept with its star, not silently
            # collapsed to the base, so the enumeration can flag it as a blind spot
            name = str(raw).strip().lower()
            if name and name.endswith("." + domain) and looks_like_host(name):
                names.add(name)
    result = Enumeration(names)
    result.truncated = truncated
    return result


def _certspotter_paged(domain: str) -> tuple[list, bool]:
    """The certspotter issuance walk with its page cap and keyless 429 fallback, returning
    the raw issuance records and whether the walk was truncated, so every reader keeps the
    per-certificate grouping the sibling guard needs and the truncation signal it may raise.

    A token raises the page cap, but the rate limit is per account, so a token whose free
    quota is spent answers 429 while the anonymous per-address bucket is a separate pool
    that may still answer. So a 429 on the token walk falls back to one keyless walk rather
    than blinding the source, and only when the keyless walk also fails is the error raised.
    """
    token = keys.certspotter_token()
    if not token:
        return _certspotter_issuances(domain, token=None, pages=_CERTSPOTTER_PAGES_KEYLESS)
    try:
        return _certspotter_issuances(domain, token=token, pages=_CERTSPOTTER_PAGES)
    except urllib.error.HTTPError as exc:
        if exc.code != 429:
            raise
        return _certspotter_issuances(domain, token=None, pages=_CERTSPOTTER_PAGES_KEYLESS)


def _certspotter_issuances(domain: str, *, token: str | None, pages: int) -> tuple[list, bool]:
    """Walk the certspotter issuance log for `domain`, returning the raw records across
    pages and whether the walk was truncated, authenticated when a token is given. The walk
    follows the `after` cursor between pages and stops at the page cap so it stays bounded. A
    walk that spends its whole page budget on full pages leaves later certificates unread, so
    it returns truncated True, while one that runs the cursor dry returns False."""
    headers = {"User-Agent": _UA, "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    records: list = []
    after = ""
    truncated = True
    for _ in range(pages):
        url = (f"https://api.certspotter.com/v1/issuances?domain={domain}"
               "&include_subdomains=true&expand=dns_names")
        if after:
            url += f"&after={after}"
        request = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(request, timeout=_TIMEOUT) as resp:
            issuances = json.loads(resp.read(_JSON_LIMIT).decode("utf-8", "replace"))
        if not isinstance(issuances, list):
            # a certspotter error is a dict, not a list, so fail loud rather than crash on
            # issuances[-1] or extend the records with its keys
            raise RuntimeError(f"certspotter returned a non-list response: {str(issuances)[:120]}")
        if not issuances:
            truncated = False
            break
        records.extend(issuances)
        after = str(issuances[-1].get("id") or "")
        if not after:
            truncated = False
            break
    return records, truncated


_VT_PAGES = 10  # cap on cursor pages, each up to the page limit, bounds a large domain


def virustotal_subdomains(domain: str) -> Enumeration:
    """Subdomains of a domain from VirusTotal, paged over the relationship cursor.

    A key buys a real per-account quota rather than the shared-address throttling the
    keyless passive sources suffer, so this is the reliable free passive source. It returns
    an empty set when no key is set, so the union simply runs without it. The walk stops at
    the page cap, and a next cursor still present at the cap means more subdomains remain
    unfetched, so the result is flagged truncated rather than passing as complete.
    """
    key = keys.virustotal_key()
    if not key:
        return Enumeration()
    headers = {"User-Agent": _UA, "Accept": "application/json", "x-apikey": key}
    names: set[str] = set()
    truncated = False
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
    for _ in range(_VT_PAGES):
        request = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(request, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read(_JSON_LIMIT).decode("utf-8", "replace"))
        names |= subdomains_from_vt(data, domain)
        url = str((data.get("links") or {}).get("next") or "")
        if not url:
            break
    else:
        # the loop hit the page cap without exhausting the cursor, so a next url still
        # present means the log has more subdomains than this bounded walk fetched
        truncated = bool(url)
    result = Enumeration(names)
    result.truncated = truncated
    return result


def subdomains_from_vt(data, domain: str) -> set[str]:
    """Subdomains from one VirusTotal relationship page, each item id is a subdomain."""
    names: set[str] = set()
    for item in data.get("data", []) or []:
        name = str(item.get("id", "")).strip().lower()
        if name and name.endswith("." + domain) and looks_like_host(name):
            names.add(name)
    return names


# OTX passive DNS is slow to answer and caps its reply at a fixed size without a cursor to
# page past, so the fetch waits longer than a normal read, and a reply at the cap is flagged
# truncated rather than passed off as the whole set.
_OTX_TIMEOUT = 60
_OTX_LIMIT = 500


def otx_subdomains(domain: str) -> Enumeration:
    """Subdomains of a domain from AlienVault OTX passive DNS, the hostnames a resolver
    actually answered for, which surfaces live hosts hidden behind a wildcard certificate
    that certificate transparency cannot see. Empty without a key, so the union runs
    without it. The endpoint caps its reply and does not page, so a reply at the cap is
    flagged truncated, invariant 5."""
    key = keys.otx_key()
    if not key:
        return Enumeration()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    request = urllib.request.Request(url, headers={"User-Agent": _UA, "X-OTX-API-KEY": key})
    with urllib.request.urlopen(request, timeout=_OTX_TIMEOUT) as resp:
        data = json.loads(resp.read(_JSON_LIMIT).decode("utf-8", "replace"))
    result = Enumeration(subdomains_from_otx(data, domain))
    result.truncated = len(data.get("passive_dns") or []) >= _OTX_LIMIT
    return result


def subdomains_from_otx(data, domain: str) -> set[str]:
    """Subdomains under `domain` named in an OTX passive-dns reply, parsed apart from the
    fetch so a test drives it without a network call."""
    names: set[str] = set()
    for row in data.get("passive_dns") or []:
        name = str(row.get("hostname", "")).strip().lower().rstrip(".")
        if name and name.endswith("." + domain) and looks_like_host(name):
            names.add(name)
    return names


# --- wayback archive: hosts and paths from a public crawl index -------------


def wayback_subdomains(domain: str) -> Enumeration:
    """Subdomains of a domain seen in the Wayback Machine CDX index, a passive read.

    Certificate logs name only hosts issued a public certificate. The archive names any host ever
    crawled or linked under the domain, so it surfaces hosts a wildcard certificate hides from the
    logs or that never held a certificate of their own, a different window than the logs. It reads
    a public index and never touches the target. One source in a union, so its failure is
    tolerated, and hitting the row cap marks the result truncated so a bounded fetch reads as a
    blind spot rather than the full set.
    """
    limit = 20000
    url = (f"http://web.archive.org/cdx/search/cdx?url={urllib.parse.quote(domain)}"
           f"&matchType=domain&output=json&fl=original&collapse=urlkey&limit={limit}")
    request = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=_TIMEOUT) as resp:
        rows = json.loads(resp.read(_JSON_LIMIT).decode("utf-8", "replace"))
    data = rows[1:] if rows and isinstance(rows[0], list) else []
    suffix = "." + domain
    names: set[str] = set()
    for row in data:
        host = (urllib.parse.urlsplit(str(row[0])).hostname or "").lower()
        if host.endswith(suffix) and looks_like_host(host):
            names.add(host)
    result = Enumeration(names)
    result.truncated = len(data) >= limit
    return result


def wayback_paths(host: str) -> set[str]:
    """Historical url paths for a host from the Wayback Machine CDX index, a passive read.

    It names paths that once existed without touching the target. It is one source in a
    union, so the caller tolerates its failure rather than letting it block the others.
    """
    url = (f"http://web.archive.org/cdx/search/cdx?url={urllib.parse.quote(host)}/*"
           "&output=json&fl=original&collapse=urlkey&limit=2000")
    request = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=_TIMEOUT) as resp:
        rows = json.loads(resp.read(_JSON_LIMIT).decode("utf-8", "replace"))
    out: set[str] = set()
    for row in rows[1:] if rows and isinstance(rows[0], list) else []:
        path = same_host_path(str(row[0]), host)
        if path:
            out.add(path)
    return out

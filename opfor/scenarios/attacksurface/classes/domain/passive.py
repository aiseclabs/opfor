"""Domain-class passive sources: certificate transparency, passive DNS, reverse-WHOIS, cves.

All standard library, no installed tool. Certificate transparency names hosts from a public
log without touching the target, an osint read. Every source here is a public read that
never touches the target, and each is an injected seam, so a test drives the scenario with
fixtures. The HTTP transport these leans on lives in `http`, imported rather than duplicated.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from opfor.scenarios.attacksurface import config
from opfor.scenarios.attacksurface.net import looks_like_host, registrable_root
from opfor.scenarios.attacksurface.classes.domain.http import _TIMEOUT, _UA
from opfor.scenarios.attacksurface.classes.domain.parsers import same_host_path


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
    OTX, and DNSDumpster.

    certspotter reads public certificate logs, VirusTotal, OTX, and DNSDumpster join when
    their key is set. VirusTotal is a reliable passive source where a keyless source is
    throttled by shared address, OTX reads passive DNS, the hostnames a resolver answered
    for, which surfaces live hosts a wildcard certificate hides from the logs, and
    DNSDumpster adds aggregated DNS records.
    All are public reads that never touch the target. Each source is best effort, an
    individual failure is tolerated so one dead source does not blind the rest, and only
    when every source fails is the failure raised, so an empty result means no records
    rather than a dead source. crt.sh once joined as a second window on the same logs, but
    it answered 502 or timed out far more often than it answered, so it was dropped, its
    data class is already covered by certspotter. A source that hit its page cap marks the
    union truncated, so a bounded fetch is reported as a blind spot rather than a full set.
    """
    sources = [certspotter_subdomains]
    if config.virustotal_key():
        sources.append(virustotal_subdomains)
    if config.otx_key():
        sources.append(otx_subdomains)
    if config.dnsdumpster_key():
        sources.append(dnsdumpster_subdomains)
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
    union = Enumeration(names)
    union.truncated = truncated
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
    token = config.certspotter_token()
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
            issuances = json.loads(resp.read().decode("utf-8", "replace"))
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
    key = config.virustotal_key()
    if not key:
        return Enumeration()
    headers = {"User-Agent": _UA, "Accept": "application/json", "x-apikey": key}
    names: set[str] = set()
    truncated = False
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
    for _ in range(_VT_PAGES):
        request = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(request, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
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
    key = config.otx_key()
    if not key:
        return Enumeration()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    request = urllib.request.Request(url, headers={"User-Agent": _UA, "X-OTX-API-KEY": key})
    with urllib.request.urlopen(request, timeout=_OTX_TIMEOUT) as resp:
        data = json.loads(resp.read().decode("utf-8", "replace"))
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


def dnsdumpster_subdomains(domain: str) -> Enumeration:
    """Subdomains of a domain from DNSDumpster's aggregated DNS records. Empty without a
    key, so the union runs without it. The free tier returns a bounded first page and bills
    for pagination, so a reply that names more A records than it returned is flagged
    truncated rather than passed off as the whole set, invariant 5."""
    key = config.dnsdumpster_key()
    if not key:
        return Enumeration()
    url = f"https://api.dnsdumpster.com/domain/{domain}"
    request = urllib.request.Request(url, headers={"User-Agent": _UA, "X-API-Key": key})
    with urllib.request.urlopen(request, timeout=_TIMEOUT) as resp:
        data = json.loads(resp.read().decode("utf-8", "replace"))
    result = Enumeration(subdomains_from_dnsdumpster(data, domain))
    try:
        total = int(data.get("total_a_recs") or 0)
    except (TypeError, ValueError):
        total = 0
    result.truncated = len(data.get("a") or []) < total
    return result


def subdomains_from_dnsdumpster(data, domain: str) -> set[str]:
    """Subdomains under `domain` named in a DNSDumpster reply, from the A and CNAME records
    whose host is a name under the target. The mail and nameserver records point off the
    domain, so the domain-suffix filter drops them. Parsed apart from the fetch so a test
    drives it without a network call."""
    names: set[str] = set()
    for record_type in ("a", "cname"):
        for row in data.get(record_type) or []:
            name = str(row.get("host", "")).strip().lower().rstrip(".")
            if name and name.endswith("." + domain) and looks_like_host(name):
                names.add(name)
    return names


# --- known vulnerabilities: cves for an identified product version -------

_NVD_TIMEOUT = 30
_NVD_MAX = 25
_NVD_MAX_REFS = 3
# NVD rate-limits by address, about one request per six seconds without a key and far more
# with one. The scan runs many hosts concurrently, so a process-wide throttle serializes
# NVD calls to stay under the limit rather than bursting into a 429. See `_nvd_wait`.
_NVD_INTERVAL_KEYLESS = 6.0
_NVD_INTERVAL_KEYED = 1.0
_NVD_RETRIES = 3
_NVD_LOCK = threading.Lock()
_nvd_next = [0.0]


def _nvd_wait(interval: float) -> None:
    """Block until at least `interval` seconds have passed since the last NVD call, across
    all threads, so concurrent scans do not burst past the rate limit."""
    with _NVD_LOCK:
        now = time.monotonic()
        wait = _nvd_next[0] - now
        if wait > 0:
            time.sleep(wait)
        _nvd_next[0] = time.monotonic() + interval


def nvd_cves(product: str, version: str, cpe: str = "") -> list[dict]:
    """CVEs affecting a product from the NVD 2.0 API, most a bounded page.

    A cpe as a `vendor:product` string matches the affected set precisely, including a range
    the version falls in, which the model supplies when it knows the product. A cpe match
    that names nothing, a wrong vendor guess or a cve not tagged with the cpe, falls back to
    a keyword search on the product so a real advisory is not missed. The keyword search uses
    the product name alone and never the version, since NVD keyword search matches the cve
    description text, and a version string almost never appears there, so adding it would
    return nothing. Whether a returned cve applies to this version and how severe is triage's
    judgment, which reads the version from the surface, not this seam. Querying NVD is a
    public read that never touches the target, keyless by default and higher-rate with a key.
    """
    if not product:
        return []
    if cpe:
        version_field = version or "*"
        match = urllib.parse.quote(f"cpe:2.3:a:{cpe}:{version_field}:*:*:*:*:*:*:*", safe="")
        results = _nvd_fetch(f"virtualMatchString={match}")
        if results:
            return results
    return _nvd_fetch(f"keywordSearch={urllib.parse.quote(product)}")


def _nvd_fetch(query: str) -> list[dict]:
    """One NVD 2.0 query, throttled and retried, returning the parsed CVE records. The
    process-wide throttle serializes concurrent scans under the rate limit, and a 429 is
    retried with a back-off that honors a Retry-After header before it is raised loud."""
    headers = {"User-Agent": _UA, "Accept": "application/json"}
    key = config.nvd_api_key()
    if key:
        headers["apiKey"] = key
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{query}&resultsPerPage={_NVD_MAX}"
    request = urllib.request.Request(url, headers=headers)
    interval = _NVD_INTERVAL_KEYED if key else _NVD_INTERVAL_KEYLESS
    for attempt in range(_NVD_RETRIES):
        _nvd_wait(interval)
        try:
            with urllib.request.urlopen(request, timeout=_NVD_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
            return cves_from_nvd(data)
        except urllib.error.HTTPError as exc:
            if exc.code != 429 or attempt == _NVD_RETRIES - 1:
                raise
            retry_after = exc.headers.get("Retry-After") if exc.headers else None
            time.sleep(float(retry_after) if retry_after and retry_after.isdigit() else interval * (attempt + 2))
    return []


def cves_from_nvd(data) -> list[dict]:
    """The id, CVSS score, severity, and summary of each CVE in an NVD 2.0 reply, parsed
    apart from the fetch so a test drives it without a network call."""
    out: list[dict] = []
    for item in data.get("vulnerabilities") or []:
        cve = item.get("cve") or {}
        cid = str(cve.get("id") or "")
        if not cid:
            continue
        score, severity = _nvd_score(cve.get("metrics") or {})
        descriptions = cve.get("descriptions") or []
        summary = next((str(d.get("value", "")) for d in descriptions if d.get("lang") == "en"), "")
        references = [str(r.get("url", "")) for r in (cve.get("references") or []) if r.get("url")]
        out.append({"id": cid, "cvss": score, "severity": severity, "summary": summary[:300],
                    "references": references[:_NVD_MAX_REFS]})
    return out


def _nvd_score(metrics) -> tuple:
    """The base score and severity from the strongest CVSS metric an NVD entry carries,
    preferring v3.1 over v3.0 over v2."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            cvss = entries[0].get("cvssData") or {}
            severity = str(cvss.get("baseSeverity") or entries[0].get("baseSeverity") or "")
            return (cvss.get("baseScore"), severity)
    return (None, "")


def hosts_from_file(path: str) -> tuple[str, ...]:
    """Read known hosts from a newline-delimited DNS export, normalized to probeable names.

    This is the DNS-export path that closes the wildcard blind spot, the operator supplies
    the hosts a wildcard certificate hides from passive discovery. A blank line or a `#`
    comment is skipped. A wildcard base such as *.dev.example.com is the real host dev.example.com.
    A leading validation label such as the `_<hash>` an ACM record uses wraps a real host,
    so it is unwrapped. A name with a control label elsewhere, such as a `_domainkey` DKIM
    record, is not a probeable host and is dropped. The result is sorted and deduplicated."""
    hosts: set[str] = set()
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            host = _host_from_record(line.strip().lower().rstrip("."))
            if host:
                hosts.add(host)
    return tuple(sorted(hosts))


def roots_from_file(path: str) -> tuple[str, ...]:
    """Read root domains from a newline-delimited file, each reduced to its registrable
    root and deduplicated. A subdomain such as www.example.com folds to example.com, so a list
    that mixes roots and hosts still yields clean roots. Normalization matches
    `hosts_from_file`, a blank or comment line and a control record are skipped."""
    roots: set[str] = set()
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            host = _host_from_record(line.strip().lower().rstrip("."))
            if host:
                roots.add(registrable_root(host))
    return tuple(sorted(roots))


def _host_from_record(name: str) -> str | None:
    """The probeable host a DNS record name refers to, or None when it names no host."""
    if not name or name.startswith("#"):
        return None
    labels = name.lstrip("*.").split(".")
    if labels and labels[0].startswith("_"):
        labels = labels[1:]                       # unwrap a leading validation label
    if any(label.startswith("_") for label in labels):
        return None                               # a control record, not a host
    host = ".".join(labels)
    if len(labels) < 2 or not looks_like_host(host):
        return None
    return host


# --- certificate SAN pivot: sibling roots that share a certificate ----------

# A certificate spanning more distinct roots than this is treated as shared multi-tenant
# infrastructure, a CDN bundling unrelated customers onto one certificate, so it proves
# no common ownership and is skipped.
_MAX_CERT_ROOTS = 5


def cert_sibling_roots(domain: str) -> dict[str, str]:
    """Registrable roots that share a certificate with `domain`, each with its evidence.

    A certificate names every host its holder proved control of to the certificate
    authority, so a root bundled on the same certificate as a known root is owned by the
    same party, evidence rather than a guess. The log is paged the same way the subdomain
    source pages it, so a sibling on a certificate past the first page is not missed. The
    parse and the multi-tenant guard live in `sibling_roots_from_issuances`, so a test
    drives them without a network call.
    """
    issuances, _ = _certspotter_paged(domain)
    return sibling_roots_from_issuances(issuances, domain)


def sibling_roots_from_issuances(issuances, domain: str) -> dict[str, str]:
    """Sibling roots from certificate-transparency issuances, guarding shared certs.

    A certificate holding the known root and only a few distinct roots is dedicated, so
    its other roots are owned by the same party. A certificate holding many distinct
    roots is shared infrastructure and proves nothing, so it is skipped. The known root
    is never returned.
    """
    known = registrable_root(domain)
    siblings: dict[str, str] = {}
    for issuance in issuances:
        names = [str(n).strip().lower().lstrip("*.") for n in issuance.get("dns_names", [])]
        roots = {registrable_root(n) for n in names if n and looks_like_host(n)}
        if known not in roots or len(roots) > _MAX_CERT_ROOTS:
            continue
        others = sorted(roots - {known})
        for root in others:
            siblings.setdefault(
                root, f"shares a certificate with {known}, {len(roots)} roots on the cert")
    return siblings


# --- reverse-WHOIS: sibling roots that share a registrant -------------------


def reverse_whois(term: str, api_key: str) -> dict[str, str]:
    """Registrable roots whose registration record names `term`, each with its evidence.

    Ownership by registration is the definitional signal of who a domain belongs to, so a
    root whose registrant matches a known registrant is owned by the same party, the most
    direct evidence there is. `term` is a registrant identity tied to the target, an
    organization name or an email. This calls one provider, the seam is injected so a
    different provider or a test fixture slots in. It has no keyless mode.
    """
    endpoint = "https://reverse-whois.whoisxmlapi.com/api/v2"
    body = json.dumps({
        "apiKey": api_key,
        "searchType": "current",
        "mode": "purchase",
        "basicSearchTerms": {"include": [term]},
    }).encode("utf-8")
    request = urllib.request.Request(
        endpoint, data=body,
        headers={"User-Agent": _UA, "Content-Type": "application/json", "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=_TIMEOUT) as resp:
        data = json.loads(resp.read().decode("utf-8", "replace"))
    return roots_from_reverse_whois(data, term)


def roots_from_reverse_whois(data, term: str) -> dict[str, str]:
    """Registrable roots from a reverse-WHOIS response body, keyed by root with evidence.

    The parse lives apart from the network call, so a test drives it with a fixture. A
    provider returns either a list of domains or a list of records naming a domain, so
    both shapes are read.
    """
    roots: dict[str, str] = {}
    for entry in data.get("domainsList", []) or []:
        name = entry if isinstance(entry, str) else str(entry.get("domainName", ""))
        name = name.strip().lower().lstrip("*.")
        if name and looks_like_host(name):
            roots.setdefault(registrable_root(name),
                             f"registration record names {term}")
    return roots


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

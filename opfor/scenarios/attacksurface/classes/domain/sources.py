"""Domain-class sources: certificate transparency, resolution, and an HTTP probe.

All standard library, no installed tool. Certificate transparency names hosts from a
public log without touching the target, an osint read. Resolution goes over DNS-over-
HTTPS to a public resolver, so it works wherever HTTPS works, even where the host's own
resolver is blocked or unreliable. The HTTP probe connects straight to a resolved
address with the hostname as SNI and Host, so it too bypasses the local resolver, and it
touches the target, so the capability marks it a scoped recon act. Each source is an
injected seam, so a test drives the scenario with fixtures.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from opfor.scenarios.attacksurface import config
from opfor.scenarios.attacksurface.net import looks_like_host, registrable_root

_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
_TIMEOUT = 12
_BODY_HEAD = 4096
# One retry on a transient timeout, so a single slow read does not mark a live host dead.
_PROBE_ATTEMPTS = 2
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_DOH_RESOLVERS = ("https://dns.google/resolve", "https://cloudflare-dns.com/dns-query")


# --- certificate transparency: subdomains without touching the target -------


# The certspotter free endpoint returns a bounded page, so a walk follows the `after`
# cursor. With a key the quota allows a full walk. Without one the free quota is tiny, so
# paging hard would exhaust it and self-throttle, so a keyless walk stays to a couple of
# pages, still the most recent certificates, and leans on the other sources for the rest.
_CERTSPOTTER_PAGES = 12
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


def certspotter_subdomains(domain: str) -> set[str]:
    """Subdomains of a domain seen in certificate transparency, via certspotter, paged.

    The free endpoint returns one bounded page, so the walk follows the `after` cursor
    across pages rather than stopping at the first, which multiplies recall many times over
    on a large log. See `_certspotter_paged` for the page cap and the keyless 429 fallback
    every certspotter reader shares.
    """
    names: set[str] = set()
    for issuance in _certspotter_paged(domain):
        for raw in issuance.get("dns_names", []):
            # a wildcard such as *.dev.example.com is kept with its star, not silently
            # collapsed to the base, so the enumeration can flag it as a blind spot
            name = str(raw).strip().lower()
            if name and name.endswith("." + domain) and looks_like_host(name):
                names.add(name)
    return names


def _certspotter_paged(domain: str) -> list:
    """The certspotter issuance walk with its page cap and keyless 429 fallback, returning
    the raw issuance records so every reader keeps the per-certificate grouping the sibling
    guard needs.

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


def _certspotter_issuances(domain: str, *, token: str | None, pages: int) -> list:
    """Walk the certspotter issuance log for `domain`, returning the raw records across
    pages, authenticated when a token is given. The walk follows the `after` cursor between
    pages and stops at the page cap so it stays bounded."""
    headers = {"User-Agent": _UA, "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    records: list = []
    after = ""
    for _ in range(pages):
        url = (f"https://api.certspotter.com/v1/issuances?domain={domain}"
               "&include_subdomains=true&expand=dns_names")
        if after:
            url += f"&after={after}"
        request = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(request, timeout=_TIMEOUT) as resp:
            issuances = json.loads(resp.read().decode("utf-8", "replace"))
        if not issuances:
            break
        records.extend(issuances)
        after = str(issuances[-1].get("id") or "")
        if not after:
            break
    return records


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

    A cpe as a `vendor:product` string with a version matches the affected version set
    precisely, which the model supplies when it knows the product, and a bare product falls
    back to a keyword search. Querying NVD is a public read that never touches the target,
    keyless by default and higher-rate with a key. It returns raw CVE facts, whether a CVE
    truly applies to the exposed surface and how severe is triage's judgment, not this.
    """
    if not product:
        return []
    headers = {"User-Agent": _UA, "Accept": "application/json"}
    key = config.nvd_api_key()
    if key:
        headers["apiKey"] = key
    if cpe and version:
        match = urllib.parse.quote(f"cpe:2.3:a:{cpe}:{version}:*:*:*:*:*:*:*", safe="")
        query = f"virtualMatchString={match}"
    else:
        query = f"keywordSearch={urllib.parse.quote((product + ' ' + version).strip())}"
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
            # A rate-limit answer is retried after a back-off, longer each attempt and
            # honoring a Retry-After header, and only a persistent limit is raised loud.
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
    return sibling_roots_from_issuances(_certspotter_paged(domain), domain)


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


# --- resolution over DNS-over-HTTPS -----------------------------------------


# DoH answer record types, the numbers RFC 1035 and RFC 3596 assign to A, AAAA, and CNAME.
_DNS_A = 1
_DNS_AAAA = 28
_DNS_CNAME = 5


def resolve_host(name: str) -> dict:
    """Resolve a name over DNS-over-HTTPS to its addresses and its CNAME chain.

    A and AAAA are both asked, so an IPv6-only host is not mistaken for a dangling one.
    The CNAME chain is kept rather than discarded, since a name that answers a CNAME but no
    address is the classic dangling-takeover signal, it points at a target that no longer
    exists. `resolvable` tracks addresses alone, so a CNAME to an unclaimed target reads as
    unresolvable with its target preserved, exactly the takeover candidate. The failure is
    raised only when every resolver errors, so a broken resolver is loud rather than a
    silent wall of false danglings.
    """
    last: Exception | None = None
    for resolver in _DOH_RESOLVERS:
        try:
            answers = _doh_answers(resolver, name, "A") + _doh_answers(resolver, name, "AAAA")
        except Exception as exc:
            last = exc
            continue
        addresses = tuple(dict.fromkeys(
            str(a["data"]) for a in answers
            if a.get("type") in (_DNS_A, _DNS_AAAA) and a.get("data")))
        cnames = tuple(dict.fromkeys(
            str(a["data"]).strip(".").lower() for a in answers
            if a.get("type") == _DNS_CNAME and a.get("data")))
        return {"resolvable": bool(addresses), "addresses": addresses, "cnames": cnames}
    raise RuntimeError(f"all DoH resolvers failed for {name}: {last}")


def _doh_answers(resolver: str, name: str, rtype: str) -> list[dict]:
    """The raw DoH answer records for one name and one record type."""
    url = f"{resolver}?name={urllib.parse.quote(name)}&type={rtype}"
    request = urllib.request.Request(
        url, headers={"Accept": "application/dns-json", "User-Agent": _UA})
    with urllib.request.urlopen(request, timeout=_TIMEOUT) as resp:
        body = json.loads(resp.read().decode("utf-8", "replace"))
    return body.get("Answer", []) or []


def public_addresses(addresses) -> list[str]:
    """The globally routable addresses among a set, so a private-only host is not probed."""
    out: list[str] = []
    for addr in addresses:
        try:
            if ipaddress.ip_address(addr).is_global:
                out.append(addr)
        except ValueError:
            continue
    return out


# --- HTTP probe, connecting to a resolved address ---------------------------


def http_probe(name: str, addresses=()) -> dict:
    """Probe a name over HTTPS then HTTP across every public address it resolves to.

    Connecting to the address with the name as SNI and Host bypasses the local resolver.
    A host with no public address is not publicly reachable, reported as not alive. Every
    public address is tried, not only the first, so a round-robin or multi-region name is
    not judged dead on one unlucky address. A timeout is transient and retried, since one
    slow read must not mark a live host dead, while a refused or reset connection is a real
    answer that moves on. Only connection errors are caught, so an unexpected error is
    raised loud rather than passing as not alive, invariant 5.
    """
    for ip in public_addresses(addresses):
        for scheme in ("https", "http"):
            for _ in range(_PROBE_ATTEMPTS):
                try:
                    status, server, _, body, location, hdrs = _connect(name, ip, scheme, "/")
                except TimeoutError:
                    continue
                except (OSError, http.client.HTTPException):
                    break
                return _result(True, status, f"{scheme}://{name}/", server, body, location, hdrs)
    return _dead()


def fetch_url(name: str, addresses, path: str) -> dict:
    """Fetch one interface path on a name by connecting to a public resolved address."""
    public = public_addresses(addresses)
    if not public:
        return {"status": None, "url": f"https://{name}{path}", "content_type": "",
                "server": "", "title": "", "body": ""}
    ip = public[0]
    for scheme in ("https", "http"):
        try:
            status, server, content_type, body, location, _hdrs = _connect(name, ip, scheme, path)
        except Exception:
            continue
        match = _TITLE.search(body)
        return {"status": status, "url": f"{scheme}://{name}{path}", "content_type": content_type,
                "server": server, "title": match.group(1).strip()[:200] if match else "",
                "body": body.lower(), "location": location}
    return {"status": None, "url": f"https://{name}{path}", "content_type": "",
            "server": "", "title": "", "body": "", "location": ""}


_PUBLIC_URL_TIMEOUT = 10
_PUBLIC_URL_BODY = 4096


def fetch_public_url(url: str) -> dict:
    """Anonymous GET of a public url, for checking a derived cloud-storage endpoint.

    A 403 or a 404 is a meaningful answer, the bucket exists but is private or it does not
    exist, so an HTTP error is captured as its status rather than raised. A connection error
    returns a null status, so a single unreachable candidate is skipped by the caller rather
    than failing the whole scan. It never sends a credential, so it reads only what is public.
    """
    request = urllib.request.Request(url, headers={"User-Agent": _UA})
    try:
        with urllib.request.urlopen(request, timeout=_PUBLIC_URL_TIMEOUT) as resp:
            body = resp.read(_PUBLIC_URL_BODY).decode("utf-8", "replace")
            return {"status": resp.status, "url": url,
                    "content_type": resp.headers.get("Content-Type", ""), "body": body}
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(_PUBLIC_URL_BODY).decode("utf-8", "replace")
        except Exception:
            body = ""
        content_type = exc.headers.get("Content-Type", "") if exc.headers else ""
        return {"status": exc.code, "url": url, "content_type": content_type, "body": body}
    except Exception:
        return {"status": None, "url": url, "content_type": "", "body": ""}


# --- self-declared interfaces: an app maps its own API --------------------

_DOCUMENT_LIMIT = 2_000_000
# A compact introspection query, enough to name the query and mutation operations without
# pulling the full type graph. When introspection answers, the surface is already mapped.
_INTROSPECTION = (
    '{"query":"{ __schema { queryType { name fields { name } } '
    'mutationType { name fields { name } } } }"}'
)


def fetch_document(name: str, path: str) -> dict:
    """Full GET of one document on a name, no body cap, for parsing a spec.

    Resolves over DNS-over-HTTPS then connects to a public address with SNI, the same way
    the probe does, so it works where the local resolver does not. A host with no public
    address is not reachable, reported as an empty document rather than raised.
    """
    public = public_addresses(resolve_host(name).get("addresses", ()))
    if not public:
        return {"status": None, "content_type": "", "text": ""}
    ip = public[0]
    for scheme in ("https", "http"):
        try:
            status, _, content_type, body, _location, _hdrs = _connect(name, ip, scheme, path, read_limit=_DOCUMENT_LIMIT)
        except Exception:
            continue
        return {"status": status, "content_type": content_type, "text": body}
    return {"status": None, "content_type": "", "text": ""}


def graphql_introspect(name: str, path: str = "/graphql") -> dict | None:
    """Introspect a GraphQL endpoint, returning the schema data or None when it is off.

    Introspection is a read, one POST with a query, no mutation, so it stays a recon act.
    A None result means introspection is disabled or the endpoint did not answer, not that
    the check failed silently, the capability turns a raised error into a loud failure.
    """
    public = public_addresses(resolve_host(name).get("addresses", ()))
    if not public:
        return None
    ip = public[0]
    body = _INTROSPECTION.encode("utf-8")
    for scheme in ("https", "http"):
        try:
            status, _, _, text, _location, _hdrs = _connect(name, ip, scheme, path, read_limit=_DOCUMENT_LIMIT,
                                                             method="POST", payload=body, content_type="application/json")
        except Exception:
            continue
        if status and 200 <= status < 300:
            try:
                data = json.loads(text)
            except Exception:
                return None
            return data.get("data") if isinstance(data, dict) and "data" in data else data
    return None


def paths_from_openapi(doc) -> list[str]:
    """Declared operations of an OpenAPI or Swagger document, each as `METHODS path`.

    Both OpenAPI 3 and Swagger 2 carry a `paths` map, so this reads that map and names the
    HTTP methods under each path. A document without a `paths` map declares nothing here.
    """
    if not isinstance(doc, dict):
        return []
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        return []
    verbs = ("get", "post", "put", "delete", "patch", "head", "options")
    out: list[str] = []
    for path, item in paths.items():
        methods = [m.upper() for m in item if m.lower() in verbs] if isinstance(item, dict) else []
        out.append(f"{','.join(sorted(methods))} {path}" if methods else str(path))
    return sorted(out)


def operations_from_introspection(data) -> list[str]:
    """Query and mutation operation names from a GraphQL introspection result."""
    schema = (data or {}).get("__schema") if isinstance(data, dict) else None
    if not isinstance(schema, dict):
        return []
    out: list[str] = []
    for key, kind in (("queryType", "query"), ("mutationType", "mutation")):
        node = schema.get(key) or {}
        for field in (node.get("fields") or []):
            name = field.get("name") if isinstance(field, dict) else None
            if name:
                out.append(f"{kind}:{name}")
    return sorted(out)


# --- candidate interface paths: robots, sitemap, javascript, passive urls ---

_SCRIPT_SRC = re.compile(r'<script[^>]+src\s*=\s*["\']([^"\']+)', re.IGNORECASE)
_JS_PATH = re.compile(r"""["'`](/[A-Za-z0-9_.\-/]{1,160})["'`]""")
_JS_URL = re.compile(r"""["'`](https?://[A-Za-z0-9.\-]+(?:/[A-Za-z0-9_.\-/]{0,200})?)["'`]""")
_LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)


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


_MAX_SECRET_MATCHES = 20


def _redact(value: str) -> str:
    """A secret shown as a short prefix and its length, never in full, so the report and the
    log never carry the value itself."""
    value = value.strip()
    head = value[:6]
    return f"{head}...({len(value)} chars)"


def secrets_in_text(text: str, patterns) -> list[dict]:
    """Secret-like strings a set of patterns match in a body, redacted, parsed apart from
    the fetch so a test drives it without a network call.

    Each pattern is a dict with an id, a regex, and a note. A match is reported once per
    pattern per body with a redacted sample, since one hit is enough to send a human to the
    source. Whether a match is a live secret or a placeholder is triage's judgment.
    """
    out: list[dict] = []
    for pattern in patterns or []:
        regex = str(pattern.get("regex", ""))
        if not regex:
            continue
        try:
            match = re.search(regex, text or "")
        except re.error:
            continue
        if not match:
            continue
        out.append({"pattern": str(pattern.get("id", "")), "note": str(pattern.get("note", "")),
                    "sample": _redact(match.group(0))})
        if len(out) >= _MAX_SECRET_MATCHES:
            break
    return out


def backup_candidates(path: str, *, append=(), rename=(), swap=()) -> list[str]:
    """Backup and editor-artifact twin paths derived from an observed file path, apart from
    the fetch so a test drives it without a network call.

    An `append` suffix is added after the full filename, `config.php` yields
    `config.php.bak`. A `rename` extension replaces the file's own extension, `config.php`
    yields `config.zip`, catching an archive of the source dropped beside it. A `swap`
    template is an editor dotfile over the filename, `{file}` yields `.config.php.swp`. A
    path with no filename segment, a directory or a query only, yields nothing. Deriving the
    twin is the mechanism here, the name lists are the data the caller hands in.
    """
    path = path.split("?")[0].split("#")[0]
    if not path.startswith("/") or path.endswith("/"):
        return []
    directory, _, filename = path.rpartition("/")
    if not filename:
        return []
    stem, dot, _ = filename.rpartition(".")
    out: list[str] = []
    for suffix in append:
        out.append(f"{directory}/{filename}{suffix}")
    if dot:
        for extension in rename:
            out.append(f"{directory}/{stem}{extension}")
    for template in swap:
        out.append(f"{directory}/{template.format(file=filename)}")
    seen: set[str] = set()
    result: list[str] = []
    for candidate in out:
        if candidate != path and candidate not in seen:
            seen.add(candidate)
            result.append(candidate)
    return result


_BUCKET_NAME = re.compile(r"^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$")
# XML listing roots each provider returns for a public, listable bucket, so a 200 that is an
# object listing is told apart from a 200 that is a generic page.
_BUCKET_LISTING_MARKERS = ("<ListBucketResult", "<EnumerationResults", "<Contents>",
                           "<Blob>", "<Blobs>")


def _valid_bucket(name: str) -> bool:
    """Whether a name is a legal object-storage bucket, the shared 3 to 63 char lowercase
    rule, so a malformed candidate is dropped before it is ever requested."""
    return bool(_BUCKET_NAME.match(name)) and ".." not in name


def bucket_candidates(bases, affixes) -> list[str]:
    """Candidate bucket names from the target's identity bases and common affixes, deduped
    and validated. Deriving the name is the mechanism here, the bases and the affixes are the
    data the caller hands in, so a new affix is a data change."""
    names: list[str] = []

    def add(name: str) -> None:
        name = name.strip(".-").lower()
        if _valid_bucket(name) and name not in names:
            names.append(name)

    for base in bases:
        base = str(base).strip().lower()
        if not base:
            continue
        add(base)
        for affix in affixes:
            affix = str(affix).strip().lower()
            if not affix:
                continue
            add(f"{base}-{affix}")
            add(f"{affix}-{base}")
            add(f"{base}.{affix}")
    return names


def bucket_listable(body: str) -> bool:
    """Whether a 200 body is a public object listing rather than a generic page."""
    return any(marker in (body or "") for marker in _BUCKET_LISTING_MARKERS)


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


def robots_entries(text: str) -> tuple[list[str], list[str]]:
    """The rule paths and the sitemap urls declared in a robots.txt.

    A Disallow or Allow line names a path the site itself knows about, often one it would
    rather not be crawled, so it is a strong candidate. A Sitemap line points at a listing
    to read for more.
    """
    paths: list[str] = []
    sitemaps: list[str] = []
    for line in (text or "").splitlines():
        line = line.strip()
        low = line.lower()
        if low.startswith(("disallow:", "allow:")):
            value = line.split(":", 1)[1].strip().split("#")[0].strip()
            if value.startswith("/") and value not in paths:
                paths.append(value)
        elif low.startswith("sitemap:"):
            value = line.split(":", 1)[1].strip()
            if value:
                sitemaps.append(value)
    return paths, sitemaps


def sitemap_paths(text: str, host: str) -> list[str]:
    """Same-host url paths listed in a sitemap.xml body, deduped."""
    out: list[str] = []
    for loc in _LOC.findall(text or ""):
        path = same_host_path(loc, host)
        if path and path not in out:
            out.append(path)
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


def same_host_path(url: str, host: str) -> str | None:
    """The path of a url when it is relative or points at host, else None. Query and
    fragment are dropped, since a path is what a probe needs."""
    url = (url or "").strip()
    if url.startswith("/") and not url.startswith("//"):
        return url.split("#")[0].split("?")[0]
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme in ("http", "https") and parsed.hostname == host:
        return parsed.path or "/"
    return None


# Response headers that carry no identification value and only add noise, dropped from the
# captured signal set. Everything else a server volunteers is kept, since the point is to
# let the model and the knowledge judge product and proxy identity, not a fixed keyword list.
_NOISE_HEADERS = frozenset((
    "date", "content-length", "content-type", "connection", "keep-alive",
    "transfer-encoding", "accept-ranges", "cache-control", "expires", "age", "vary",
    "etag", "last-modified", "content-encoding", "content-language", "pragma",
    "alt-svc", "report-to", "nel", "strict-transport-security", "content-security-policy",
))
_MAX_HEADERS = 24
_MAX_HEADER_VALUE = 160


def _signal_headers(resp) -> tuple:
    """The response headers worth keeping for identification, name lowercased and value
    bounded. A `set-cookie` is reduced to its cookie name, since the name is signal and the
    value is a secret. Noise headers are dropped, everything else a server volunteers is
    kept for the model to judge."""
    out: list[tuple[str, str]] = []
    for raw_name, raw_value in resp.getheaders():
        name = str(raw_name).strip().lower()
        if name in _NOISE_HEADERS:
            continue
        value = str(raw_value).strip()
        if name == "set-cookie":
            value = value.split("=", 1)[0].strip()
        out.append((name, value[:_MAX_HEADER_VALUE]))
        if len(out) >= _MAX_HEADERS:
            break
    return tuple(out)


def _connect(name: str, ip: str, scheme: str, path: str, *, read_limit: int = _BODY_HEAD,
             method: str = "GET", payload: bytes | None = None,
             content_type: str = "") -> tuple:
    """One request to ip, with SNI and Host set to name, returning status and shape.

    Certificate validation is off on purpose, a recon probe records what a server serves,
    a self-signed or mismatched certificate is itself signal, not a reason to skip. The
    read limit is a full document when a caller needs to parse a body such as a spec, and
    a payload turns the request into a POST for a GraphQL introspection.
    """
    if scheme == "https":
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((ip, 443), timeout=_TIMEOUT)
        sock = context.wrap_socket(raw, server_hostname=name)
        conn = http.client.HTTPSConnection(name, timeout=_TIMEOUT)
        conn.sock = sock
    else:
        conn = http.client.HTTPConnection(ip, 80, timeout=_TIMEOUT)
    headers = {"Host": name, "User-Agent": _UA}
    if content_type:
        headers["Content-Type"] = content_type
    try:
        conn.request(method, path or "/", body=payload, headers=headers)
        resp = conn.getresponse()
        body = resp.read(read_limit).decode("utf-8", "replace")
        return (resp.status, resp.getheader("Server", "") or "",
                resp.getheader("Content-Type", "") or "", body,
                resp.getheader("Location", "") or "", _signal_headers(resp))
    finally:
        conn.close()


def _result(alive: bool, status, url: str, server: str, body: str, location: str = "",
            headers: tuple = ()) -> dict:
    match = _TITLE.search(body)
    return {"alive": alive, "status": status, "url": url, "server": server,
            "title": match.group(1).strip()[:200] if match else "", "body": body.lower(),
            "location": location, "headers": headers}


def _dead() -> dict:
    return {"alive": False, "status": None, "url": "", "server": "", "title": "", "body": "",
            "location": "", "headers": ()}

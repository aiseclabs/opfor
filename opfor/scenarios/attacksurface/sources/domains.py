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
import urllib.error
import urllib.parse
import urllib.request

from opfor.scenarios.attacksurface import config

_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
_TIMEOUT = 12
_BODY_HEAD = 4096
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_DOH_RESOLVERS = ("https://dns.google/resolve", "https://cloudflare-dns.com/dns-query")


# --- certificate transparency: subdomains without touching the target -------


# The certspotter free endpoint returns a bounded page, so a walk follows the `after`
# cursor. With a key the quota allows a full walk. Without one the free quota is tiny, so
# paging hard would exhaust it and self-throttle, so a keyless walk stays to a couple of
# pages, still the most recent certificates, and leans on the other sources for the rest.
_CERTSPOTTER_PAGES = 12
_CERTSPOTTER_PAGES_KEYLESS = 2


def subdomains(domain: str) -> set[str]:
    """Passive subdomains of a domain, the union of certificate transparency and VirusTotal.

    certspotter and crt.sh read public certificate logs, VirusTotal joins when a key is
    set and is the reliable passive source, since a keyless source is throttled by shared
    address. All are public reads that never touch the target. Each source is best effort,
    an individual failure is tolerated so one dead source does not blind the rest, and only
    when every source fails is the failure raised, so an empty result means no records
    rather than a dead source.
    """
    sources = [certspotter_subdomains, crt_subdomains]
    if config.virustotal_key():
        sources.append(virustotal_subdomains)
    names: set[str] = set()
    errors: list[str] = []
    for source in sources:
        try:
            names |= source(domain)
        except Exception as exc:
            errors.append(f"{source.__name__}: {exc}")
    if not names and len(errors) == len(sources):
        raise RuntimeError("all passive subdomain sources failed: " + ", ".join(errors))
    return names


def certspotter_subdomains(domain: str) -> set[str]:
    """Subdomains of a domain seen in certificate transparency, via certspotter, paged.

    The free endpoint returns one bounded page, so this follows the `after` cursor to walk
    the log rather than stopping at the first page, which multiplies recall many times over
    on a large log. It stops at a page cap so the walk stays bounded.
    """
    headers = {"User-Agent": _UA, "Accept": "application/json"}
    token = config.certspotter_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    pages = _CERTSPOTTER_PAGES if token else _CERTSPOTTER_PAGES_KEYLESS
    names: set[str] = set()
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
        for issuance in issuances:
            for raw in issuance.get("dns_names", []):
                name = str(raw).strip().lower().lstrip("*.")
                if name and name.endswith("." + domain) and _looks_like_host(name):
                    names.add(name)
        after = str(issuances[-1].get("id") or "")
        if not after:
            break
    return names


def crt_subdomains(domain: str) -> set[str]:
    """Subdomains of a domain seen in certificate transparency, via crt.sh."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    request = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=_TIMEOUT) as resp:
        rows = json.loads(resp.read().decode("utf-8", "replace"))
    names: set[str] = set()
    for row in rows:
        raw = str(row.get("name_value", "")) + "\n" + str(row.get("common_name", ""))
        for line in raw.split("\n"):
            name = line.strip().lower().lstrip("*.")
            if name and name.endswith("." + domain) and _looks_like_host(name):
                names.add(name)
    return names


_VT_PAGES = 10  # cap on cursor pages, each up to the page limit, bounds a large domain


def virustotal_subdomains(domain: str) -> set[str]:
    """Subdomains of a domain from VirusTotal, paged over the relationship cursor.

    A key buys a real per-account quota rather than the shared-address throttling the
    keyless passive sources suffer, so this is the reliable free passive source. It returns
    an empty set when no key is set, so the union simply runs without it.
    """
    key = config.virustotal_key()
    if not key:
        return set()
    headers = {"User-Agent": _UA, "Accept": "application/json", "x-apikey": key}
    names: set[str] = set()
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
    for _ in range(_VT_PAGES):
        request = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(request, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        names |= subdomains_from_vt(data, domain)
        url = str((data.get("links") or {}).get("next") or "")
        if not url:
            break
    return names


def subdomains_from_vt(data, domain: str) -> set[str]:
    """Subdomains from one VirusTotal relationship page, each item id is a subdomain."""
    names: set[str] = set()
    for item in data.get("data", []) or []:
        name = str(item.get("id", "")).strip().lower().lstrip("*.")
        if name and name.endswith("." + domain) and _looks_like_host(name):
            names.add(name)
    return names


def _looks_like_host(name: str) -> bool:
    return "@" not in name and " " not in name and all(part for part in name.split("."))


# --- certificate SAN pivot: sibling roots that share a certificate ----------

# A curated subset of multi-label public suffixes, so registrable-root extraction does
# not mistake a country second level such as co.uk for a root. A single-label suffix
# falls through to the two-label default, which is correct for com, io, and the like.
_MULTI_SUFFIXES = frozenset({
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "or.jp", "ne.jp",
    "com.cn", "net.cn", "org.cn", "gov.cn", "com.hk", "org.hk",
    "com.au", "net.au", "org.au", "com.sg", "com.br", "com.tw",
    "co.kr", "co.in", "co.za", "com.mx", "com.tr", "com.ru",
})

# A certificate spanning more distinct roots than this is treated as shared multi-tenant
# infrastructure, a CDN bundling unrelated customers onto one certificate, so it proves
# no common ownership and is skipped.
_MAX_CERT_ROOTS = 5


def registrable_root(name: str) -> str:
    """The registrable root of a host, example.com for api.example.com, using a small
    multi-label suffix set so co.uk and its kind keep three labels."""
    labels = name.strip(".").lower().split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in _MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def cert_sibling_roots(domain: str) -> dict[str, str]:
    """Registrable roots that share a certificate with `domain`, each with its evidence.

    A certificate names every host its holder proved control of to the certificate
    authority, so a root bundled on the same certificate as a known root is owned by the
    same party, evidence rather than a guess. The parse and the multi-tenant guard live
    in `sibling_roots_from_issuances`, so a test drives them without a network call.
    """
    url = (f"https://api.certspotter.com/v1/issuances?domain={domain}"
           "&include_subdomains=true&expand=dns_names")
    request = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=_TIMEOUT) as resp:
        issuances = json.loads(resp.read().decode("utf-8", "replace"))
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
        roots = {registrable_root(n) for n in names if n and _looks_like_host(n)}
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
        if name and _looks_like_host(name):
            roots.setdefault(registrable_root(name),
                             f"registration record names {term}")
    return roots


# --- resolution over DNS-over-HTTPS -----------------------------------------


def resolve_host(name: str) -> dict:
    """Resolve a name to its A records over DNS-over-HTTPS, or mark it unresolvable.

    An empty answer is a real result, the name has no address, a dangling candidate. The
    failure is raised only when every resolver errors, so a broken resolver is loud rather
    than a silent wall of false danglings.
    """
    last: Exception | None = None
    for resolver in _DOH_RESOLVERS:
        try:
            addresses = _doh_a(resolver, name)
            return {"resolvable": bool(addresses), "addresses": tuple(addresses)}
        except Exception as exc:
            last = exc
    raise RuntimeError(f"all DoH resolvers failed for {name}: {last}")


def _doh_a(resolver: str, name: str) -> list[str]:
    url = f"{resolver}?name={urllib.parse.quote(name)}&type=A"
    request = urllib.request.Request(
        url, headers={"Accept": "application/dns-json", "User-Agent": _UA})
    with urllib.request.urlopen(request, timeout=_TIMEOUT) as resp:
        body = json.loads(resp.read().decode("utf-8", "replace"))
    return [str(a["data"]) for a in body.get("Answer", []) if a.get("type") == 1 and a.get("data")]


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
    """Probe a name over HTTPS then HTTP by connecting to a public address it resolves to.

    Connecting to the address with the name as SNI and Host bypasses the local resolver.
    A host with no public address is not publicly reachable, reported as not alive. A
    connection error on both schemes is a real answer, not raised.
    """
    public = public_addresses(addresses)
    if not public:
        return _dead()
    ip = public[0]
    for scheme in ("https", "http"):
        try:
            status, server, _, body = _connect(name, ip, scheme, "/")
        except Exception:
            continue
        return _result(True, status, f"{scheme}://{name}/", server, body)
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
            status, server, content_type, body = _connect(name, ip, scheme, path)
        except Exception:
            continue
        match = _TITLE.search(body)
        return {"status": status, "url": f"{scheme}://{name}{path}", "content_type": content_type,
                "server": server, "title": match.group(1).strip()[:200] if match else "",
                "body": body.lower()}
    return {"status": None, "url": f"https://{name}{path}", "content_type": "",
            "server": "", "title": "", "body": ""}


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
            status, _, content_type, body = _connect(name, ip, scheme, path, read_limit=_DOCUMENT_LIMIT)
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
            status, _, _, text = _connect(name, ip, scheme, path, read_limit=_DOCUMENT_LIMIT,
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
        return resp.status, resp.getheader("Server", "") or "", resp.getheader("Content-Type", "") or "", body
    finally:
        conn.close()


def _result(alive: bool, status, url: str, server: str, body: str) -> dict:
    match = _TITLE.search(body)
    return {"alive": alive, "status": status, "url": url, "server": server,
            "title": match.group(1).strip()[:200] if match else "", "body": body.lower()}


def _dead() -> dict:
    return {"alive": False, "status": None, "url": "", "server": "", "title": "", "body": ""}

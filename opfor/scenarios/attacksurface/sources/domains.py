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

_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
_TIMEOUT = 12
_BODY_HEAD = 4096
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_DOH_RESOLVERS = ("https://dns.google/resolve", "https://cloudflare-dns.com/dns-query")


# --- certificate transparency: subdomains without touching the target -------


def subdomains(domain: str) -> set[str]:
    """Certificate-transparency subdomains of a domain, certspotter first, crt.sh next.

    Both are public logs of issued certificates, so they name hosts without touching the
    target. certspotter leads because it is fast and reliable, crt.sh is the fallback and
    is often slow or 503 under load. Only when both fail is the failure raised, never
    swallowed into an empty set, so an empty result means no certificates, not a dead
    source.
    """
    try:
        return certspotter_subdomains(domain)
    except Exception as first:
        try:
            return crt_subdomains(domain)
        except Exception as second:
            raise RuntimeError(f"certspotter failed ({first}), crt.sh failed ({second})") from second


def certspotter_subdomains(domain: str) -> set[str]:
    """Subdomains of a domain seen in certificate transparency, via certspotter."""
    url = (f"https://api.certspotter.com/v1/issuances?domain={domain}"
           "&include_subdomains=true&expand=dns_names")
    request = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=_TIMEOUT) as resp:
        issuances = json.loads(resp.read().decode("utf-8", "replace"))
    names: set[str] = set()
    for issuance in issuances:
        for raw in issuance.get("dns_names", []):
            name = str(raw).strip().lower().lstrip("*.")
            if name and name.endswith("." + domain) and _looks_like_host(name):
                names.add(name)
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


def _looks_like_host(name: str) -> bool:
    return "@" not in name and " " not in name and all(part for part in name.split("."))


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


def _connect(name: str, ip: str, scheme: str, path: str) -> tuple:
    """One GET to ip, with SNI and Host set to name, returning status and shape.

    Certificate validation is off on purpose, a recon probe records what a server serves,
    a self-signed or mismatched certificate is itself signal, not a reason to skip.
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
    try:
        conn.request("GET", path or "/", headers={"Host": name, "User-Agent": _UA})
        resp = conn.getresponse()
        body = resp.read(_BODY_HEAD).decode("utf-8", "replace")
        return resp.status, resp.getheader("Server", "") or "", resp.getheader("Content-Type", "") or "", body
    finally:
        conn.close()


def _result(alive: bool, status, url: str, server: str, body: str) -> dict:
    match = _TITLE.search(body)
    return {"alive": alive, "status": status, "url": url, "server": server,
            "title": match.group(1).strip()[:200] if match else "", "body": body.lower()}


def _dead() -> dict:
    return {"alive": False, "status": None, "url": "", "server": "", "title": "", "body": ""}

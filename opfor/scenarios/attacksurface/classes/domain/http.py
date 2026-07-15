"""Domain-class HTTP and DNS transport: resolution over DNS-over-HTTPS and an HTTP probe.

All standard library, no installed tool. Resolution goes over DNS-over-HTTPS to a public
resolver, so it works wherever HTTPS works, even where the host's own resolver is blocked
or unreliable. The HTTP probe connects straight to a resolved address with the hostname as
SNI and Host, so it too bypasses the local resolver, and it touches the target, so the
capability marks it a scoped recon act. Each seam is injected, so a test drives the
scenario with fixtures.

Operator note on TLS: the recon probe does not verify the target certificate on purpose, a
self-signed or mismatched certificate is itself a signal and refusing it would blind the
scan. The trade-off is that content read over that unverified channel could be spoofed by a
man in the middle and become a finding. The read-only reproduce replay verifies the
certificate, so a spoofed finding on an https target fails to reproduce, which bounds how
far a man-in-the-middle fabrication can travel.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
_TIMEOUT = 12
_BODY_HEAD = 4096
# One retry on a transient timeout, so a single slow read does not mark a live host dead.
_PROBE_ATTEMPTS = 2
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_DOH_RESOLVERS = ("https://dns.google/resolve", "https://cloudflare-dns.com/dns-query")


# --- resolution over DNS-over-HTTPS -----------------------------------------


# DoH answer record types, the numbers RFC 1035 and RFC 3596 assign to A, AAAA, and CNAME.
_DNS_A = 1
_DNS_AAAA = 28
_DNS_CNAME = 5
# A ceiling on a JSON response body read from a resolver or a passive source, so a degenerate
# or hostile upstream cannot exhaust memory with a multi-gigabyte reply. Generous, since a
# real certificate-transparency or vulnerability response for a large domain can be several
# megabytes, but bounded.
_JSON_LIMIT = 8_000_000
# DoH response codes. NOERROR and NXDOMAIN are real answers, a name that resolves or one that
# provably does not exist. Any other rcode, SERVFAIL or REFUSED, is a resolver-side error, not
# a confirmed absence of an address.
_DNS_NOERROR = 0
_DNS_NXDOMAIN = 3


def resolve_host(name: str) -> dict:
    """Resolve a name over DNS-over-HTTPS to its addresses and its CNAME chain.

    A and AAAA are both asked, so an IPv6-only host is not mistaken for a dangling one.
    The CNAME chain is kept rather than discarded, since a name that answers a CNAME but no
    address is the classic dangling-takeover signal, it points at a target that no longer
    exists. `resolvable` tracks addresses alone, so a CNAME to an unclaimed target reads as
    unresolvable with its target preserved, exactly the takeover candidate.

    A resolver-side error rcode such as SERVFAIL, an HTTP 200 with an empty answer, is not a
    confirmed no-address, so it is treated like a failed resolver, the next one is tried, and
    only when every resolver errors is the failure raised. This keeps a transient resolver
    problem from becoming a wall of false danglings.
    """
    last: Exception | None = None
    for resolver in _DOH_RESOLVERS:
        try:
            a_status, a_ans = _doh_query(resolver, name, "A")
            aaaa_status, aaaa_ans = _doh_query(resolver, name, "AAAA")
        except Exception as exc:
            last = exc
            continue
        real = (_DNS_NOERROR, _DNS_NXDOMAIN)
        if a_status not in real and aaaa_status not in real:
            last = RuntimeError(f"DoH resolver error for {name}, rcodes A={a_status} AAAA={aaaa_status}")
            continue
        answers = a_ans + aaaa_ans
        addresses = tuple(dict.fromkeys(
            str(a["data"]) for a in answers
            if a.get("type") in (_DNS_A, _DNS_AAAA) and a.get("data")))
        cnames = tuple(dict.fromkeys(
            str(a["data"]).strip(".").lower() for a in answers
            if a.get("type") == _DNS_CNAME and a.get("data")))
        return {"resolvable": bool(addresses), "addresses": addresses, "cnames": cnames}
    raise RuntimeError(f"all DoH resolvers failed for {name}: {last}")


def _doh_query(resolver: str, name: str, rtype: str) -> tuple[int, list[dict]]:
    """The DoH response code and answer records for one name and one record type. The rcode
    is returned alongside the answers so a resolver error is told apart from a real no-answer."""
    url = f"{resolver}?name={urllib.parse.quote(name)}&type={rtype}"
    request = urllib.request.Request(
        url, headers={"Accept": "application/dns-json", "User-Agent": _UA})
    with urllib.request.urlopen(request, timeout=_TIMEOUT) as resp:
        body = json.loads(resp.read(_JSON_LIMIT).decode("utf-8", "replace"))
    return int(body.get("Status", 0)), (body.get("Answer") or [])


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
    """Fetch one interface path on a name by connecting to a public resolved address.

    Every public address is tried, not only the first, the same way the alive probe does, so
    a host that answers on a later address is enriched rather than read as empty because its
    first address is dead. A null status is returned only when no address answered on either
    scheme, so the caller can tell a transport failure from a real absent path, invariant 5.
    """
    public = public_addresses(addresses)
    if not public:
        return {"status": None, "url": f"https://{name}{path}", "content_type": "",
                "server": "", "title": "", "body": ""}
    for ip in public:
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
        # do not follow a redirect, a server-controlled Location could steer this at another
        # host, and the bucket state is read from the direct response, not a chased one
        with _NO_REDIRECT_OPENER.open(request, timeout=_PUBLIC_URL_TIMEOUT) as resp:
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


# The read-only reproduce replay must never follow a redirect. Following one would chase a
# server-controlled Location, which can be an off-scope host or a GET that triggers an
# action, breaking the read-only and in-scope guarantees. A larger body cap than the bucket
# probe, so the receipt size reflects a real exposed document rather than a 4096-byte floor.
_REPRODUCE_BODY = 262_144


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect handler that never redirects, so a 3xx is returned raw rather than chased."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirect)


def fetch_readonly(url: str) -> dict:
    """A single GET for the read-only reproduce replay, connected to a vetted public address.

    The host is resolved and filtered to its public addresses, and the request is pinned to
    that address, so a name repointed at a private or link-local target between observation
    and replay cannot steer the replay at an internal host, the same private-IP guard every
    other probe uses. The certificate is verified, so a man in the middle cannot feed the
    replay fabricated content. A redirect is captured raw with its Location, never followed,
    so an off-site or login redirect is recorded rather than chased. A host with no public
    address, or one that does not answer, returns a null status.
    """
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    scheme = parts.scheme or "https"
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    empty = {"status": None, "url": url, "content_type": "", "location": "", "body": ""}
    public = public_addresses(resolve_host(host).get("addresses", ()))
    if not public:
        return empty
    for ip in public:
        try:
            status, _server, content_type, body, location, _headers = _connect(
                host, ip, scheme, path, read_limit=_REPRODUCE_BODY, verify=True)
        except Exception:
            continue
        return {"status": status, "url": url, "content_type": content_type,
                "location": location, "body": body}
    return empty


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
    for ip in public:
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
    A None result means introspection is genuinely off, the endpoint answered and declined,
    a 2xx without schema data or a client-side 4xx refusal. An errored probe is raised loud
    instead, a 5xx, an unparseable 2xx body, or no answer on any address, so an endpoint that
    could not be checked is never read as safely disabled, invariant 5. Every public address
    is tried, not only the first.
    """
    public = public_addresses(resolve_host(name).get("addresses", ()))
    if not public:
        raise RuntimeError(f"graphql introspection has no public address for {name!r}")
    body = _INTROSPECTION.encode("utf-8")
    for ip in public:
        for scheme in ("https", "http"):
            try:
                status, _, _, text, _location, _hdrs = _connect(
                    name, ip, scheme, path, read_limit=_DOCUMENT_LIMIT,
                    method="POST", payload=body, content_type="application/json")
            except Exception:
                continue
            if status is None:
                continue
            if 200 <= status < 300:
                try:
                    data = json.loads(text)
                except Exception as exc:
                    raise RuntimeError(f"graphql 2xx body was not JSON: {type(exc).__name__}")
                if isinstance(data, dict) and "data" in data:
                    return data["data"]
                return None
            if 400 <= status < 500:
                return None
            raise RuntimeError(f"graphql introspection errored, HTTP {status}")
    raise RuntimeError(f"graphql introspection got no answer on any address for {name!r}")


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


_READ_CHUNK = 65536
# A wall-clock ceiling on reading one response body. The per-recv socket timeout does not
# bound total read time, so a server that dribbles bytes just under it could tie a worker
# thread for the whole body. This caps the total, so a slow-drip host cannot stall the run.
_READ_DEADLINE = 30.0


def _read_capped(resp, read_limit: int) -> bytes:
    """Read up to read_limit bytes, stopping at a wall-clock deadline. `read1` returns the
    bytes already available rather than blocking for a full chunk, so the deadline is checked
    often and a slow-drip response cannot hold a worker past the ceiling."""
    deadline = time.monotonic() + _READ_DEADLINE
    buf = bytearray()
    while len(buf) < read_limit:
        chunk = resp.read1(min(_READ_CHUNK, read_limit - len(buf)))
        if not chunk:
            break
        buf.extend(chunk)
        if time.monotonic() > deadline:
            break
    return bytes(buf)


def _connect(name: str, ip: str, scheme: str, path: str, *, read_limit: int = _BODY_HEAD,
             method: str = "GET", payload: bytes | None = None,
             content_type: str = "", verify: bool = False) -> tuple:
    """One request to ip, with SNI and Host set to name, returning status and shape.

    Certificate validation is off by default on purpose, a recon probe records what a server
    serves, a self-signed or mismatched certificate is itself signal, not a reason to skip.
    A caller that acts on the content, such as the read-only reproduce replay, passes
    `verify=True` so a man in the middle cannot feed it fabricated content over a trusted
    channel. The read limit is a full document when a caller needs to parse a body such as a
    spec, and a payload turns the request into a POST for a GraphQL introspection.
    """
    if scheme == "https":
        context = ssl.create_default_context()
        if not verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((ip, 443), timeout=_TIMEOUT)
        # Close the raw socket if the TLS handshake fails, else a host that keeps 443 open but
        # is not TLS leaks a file descriptor on every probe and a scan exhausts the fd limit.
        try:
            sock = context.wrap_socket(raw, server_hostname=name)
        except Exception:
            raw.close()
            raise
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
        body = _read_capped(resp, read_limit).decode("utf-8", "replace")
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

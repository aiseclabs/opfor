"""Domain-class HTTP transport: an HTTP probe and the read fetches that build on it.

All standard library, no installed tool. The probe resolves a name over DNS-over-HTTPS,
see the dns module, then connects straight to a resolved address with the hostname as SNI
and Host, so it bypasses the local resolver, and it touches the target, so the capability
marks it a scoped recon act. Each seam is injected, so a test drives the scenario with
fixtures. Resolution, the shared network constants, and address filtering live in the dns
module, this module imports them.

Operator note on TLS: the recon probe does not verify the target certificate on purpose, a
self-signed or mismatched certificate is itself a signal and refusing it would blind the
scan. The trade-off is that content read over that unverified channel could be spoofed by a
man in the middle and become a finding, so a finding grounded on an https read is a recon
observation, not a verified fact.
"""

from __future__ import annotations

import http.client
import json
import re
import socket
import ssl
import time

from opfor.scenarios.attacksurface.assets.domain.sources.dns import (
    _TIMEOUT,
    _UA,
    public_addresses,
    resolve_host,
)
from opfor.scenarios.attacksurface.assets.domain.sources.observations import Liveness, Response

_BODY_HEAD = 4096
# A product's own version endpoint, such as a settings document, can bury the version deep in a
# large body, so an interface path that carries a version is read to this larger cap rather than the
# head floor, else a real version is missed. Only the identification paths a product declares read
# this far, generic probing stays at the head floor, and the model view is bounded elsewhere by render.
_BODY_VERSION = 32768
# One retry on a transient timeout, so a single slow read does not mark a live host dead.
_PROBE_ATTEMPTS = 2
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


# --- HTTP probe, connecting to a resolved address ---------------------------


def http_probe(name: str, addresses=()) -> Liveness:
    """Probe a name over HTTPS then HTTP across every public address it resolves to.

    Connecting to the address with the name as SNI and Host bypasses the local resolver.
    A host with no public address is not publicly reachable, reported as not alive. Every
    public address is tried, not only the first, so a round-robin or multi-region name is
    not judged dead on one unlucky address. A timeout is transient and retried, since one
    slow read must not mark a live host dead, while a refused or reset connection is a real
    answer that moves on. Only connection errors are caught, so an unexpected error is
    raised loud rather than passing as not alive, invariant 5.

    When no address answers, the reason is kept so the caller tells a genuine negative from a
    coverage gap, invariant 3. A refused or reset connection is evidence there is no web
    service, a real negative. A uniform timeout across every address and scheme is evidence
    the run could not reach the host at all, filtered or down, a gap in coverage rather than a
    confirmed absence, so the caller records it rather than reading a clean not-alive.
    """
    public = public_addresses(addresses)
    if not public:
        return _dead("no-public-address")
    refused = False
    for ip in public:
        for scheme in ("https", "http"):
            for _ in range(_PROBE_ATTEMPTS):
                try:
                    status, server, _, body, location, hdrs = _connect(name, ip, scheme, "/")
                except TimeoutError:
                    continue
                except (OSError, http.client.HTTPException):
                    refused = True
                    break
                return _result(True, status, f"{scheme}://{name}/", server, body, location, hdrs)
    return _dead("refused" if refused else "unreachable")


def fetch_url(name: str, addresses, path: str, *, body_limit: int = _BODY_HEAD) -> Response:
    """Fetch one interface path on a name by connecting to a public resolved address.

    Every public address is tried, not only the first, the same way the alive probe does, so
    a host that answers on a later address is enriched rather than read as empty because its
    first address is dead. A null status is returned only when no address answered, and it
    carries a `reason`, `no-public-address` or `unreachable`, so the caller tells a transport
    failure from a real absent path, invariant 5. Only transport errors are caught, so an
    unexpected error is raised loud rather than swallowed as a null status, the same loud
    contract the alive probe keeps. `body_limit` is how far the body is read, the head floor by
    default and a larger cap for a product version endpoint whose version sits deep in the body.
    """
    public = public_addresses(addresses)
    if not public:
        return _no_url_answer(name, path, "no-public-address")
    for ip in public:
        for scheme in ("https", "http"):
            try:
                status, server, content_type, body, location, _hdrs = _connect(
                    name, ip, scheme, path, read_limit=body_limit)
            except (OSError, http.client.HTTPException):
                continue
            match = _TITLE.search(body)
            return Response(status=status, url=f"{scheme}://{name}{path}", content_type=content_type,
                            server=server, title=match.group(1).strip()[:200] if match else "",
                            body=body.lower(), location=location, reason="")
    return _no_url_answer(name, path, "unreachable")


def _no_url_answer(name: str, path: str, reason: str) -> Response:
    """A null-status `fetch_url` result carrying why no address answered, so the shape is the
    same as a real answer and the caller reads the reason rather than guessing at a bare null."""
    return Response(status=None, url=f"https://{name}{path}", reason=reason)


# --- self-declared interfaces: an app maps its own API --------------------

_DOCUMENT_LIMIT = 2_000_000
# A compact introspection query, enough to name the query and mutation operations without
# pulling the full type graph. When introspection answers, the surface is already mapped.
_INTROSPECTION = (
    '{"query":"{ __schema { queryType { name fields { name } } '
    'mutationType { name fields { name } } } }"}'
)


def fetch_document(name: str, path: str) -> Response:
    """Full GET of one document on a name, no body cap, for parsing a spec.

    Resolves over DNS-over-HTTPS then connects to a public address with SNI, the same way
    the probe does, so it works where the local resolver does not. A host with no public
    address, or one that does not answer, returns a null status carrying why,
    `no-public-address` or `unreachable`, rather than a bare empty document a caller could
    read as a real no-content answer. Only transport errors are caught, so an unexpected
    error is raised loud rather than swallowed as a null status, invariant 5.
    """
    public = public_addresses(resolve_host(name).addresses)
    if not public:
        return Response(status=None, reason="no-public-address")
    for ip in public:
        for scheme in ("https", "http"):
            try:
                status, _, content_type, body, _location, _hdrs = _connect(
                    name, ip, scheme, path, read_limit=_DOCUMENT_LIMIT)
            except (OSError, http.client.HTTPException):
                continue
            return Response(status=status, content_type=content_type, body=body, reason="")
    return Response(status=None, reason="unreachable")


def graphql_introspect(name: str, path: str = "/graphql") -> dict | None:
    """Introspect a GraphQL endpoint, returning the schema data or None when it is off.

    Introspection is a read, one POST with a query, no mutation, so it stays a recon act.
    A None result means introspection is genuinely off, the endpoint answered and declined,
    a 2xx without schema data or a client-side 4xx refusal. An errored probe is raised loud
    instead, a 5xx, an unparseable 2xx body, or no answer on any address, so an endpoint that
    could not be checked is never read as safely disabled, invariant 5. Every public address
    is tried, not only the first.
    """
    public = public_addresses(resolve_host(name).addresses)
    if not public:
        raise RuntimeError(f"graphql introspection has no public address for {name!r}")
    body = _INTROSPECTION.encode("utf-8")
    for ip in public:
        for scheme in ("https", "http"):
            try:
                status, _, _, text, _location, _hdrs = _connect(
                    name, ip, scheme, path, read_limit=_DOCUMENT_LIMIT,
                    method="POST", payload=body, content_type="application/json")
            except (OSError, http.client.HTTPException):
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


# --- response header signal --------------------------------------------------

# Response headers that carry no identification value and only add noise, dropped from the
# captured signal set. Everything else a server volunteers is kept, since the point is to
# let the model and the knowledge judge product and proxy identity, not a fixed keyword list.
_NOISE_HEADERS = frozenset((
    "date", "content-length", "content-type", "connection", "keep-alive",
    "transfer-encoding", "accept-ranges", "cache-control", "expires", "age", "vary",
    "etag", "last-modified", "content-encoding", "content-language", "pragma",
    "alt-svc", "report-to", "nel",
))
# The response security headers whose presence, value, or absence is a finding. Kept out of
# the noise set so they are captured, and kept complete past the identification cap by
# `_signal_headers`, so the surface report states the full set a host sets and triage reads a
# missing one as genuinely absent rather than dropped to bound the prompt.
SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)
_MAX_HEADERS = 24
_MAX_HEADER_VALUE = 160


def _signal_headers(resp) -> tuple:
    """The response headers worth keeping for identification, name lowercased and value
    bounded. A `set-cookie` is reduced to its cookie name and attributes with the value
    dropped, so its Secure, HttpOnly, and SameSite flags stay visible for triage while the
    secret value never enters the report. Noise headers are dropped, everything else a server
    volunteers is kept for the model to judge. The security headers are always kept, ahead of
    the identification cap, so triage sees the complete set a host sets and reads an absent one
    as genuinely absent rather than one dropped to bound the prompt."""
    security: list[tuple[str, str]] = []
    other: list[tuple[str, str]] = []
    for raw_name, raw_value in resp.getheaders():
        name = str(raw_name).strip().lower()
        if name in _NOISE_HEADERS:
            continue
        value = str(raw_value).strip()
        if name == "set-cookie":
            value = _redact_cookie(value)
        pair = (name, value[:_MAX_HEADER_VALUE])
        (security if name in SECURITY_HEADERS else other).append(pair)
    return tuple(security + other[:max(0, _MAX_HEADERS - len(security))])


def _redact_cookie(value: str) -> str:
    """A Set-Cookie reduced to its cookie name and attributes, dropping the value. The value
    is the secret, so it never enters the report, while the name and the Secure, HttpOnly, and
    SameSite attributes stay so triage can judge whether a cookie is set safely. A flag not
    listed here is genuinely absent on the cookie, since every attribute but the value is
    kept."""
    parts = [segment.strip() for segment in value.split(";")]
    name = parts[0].split("=", 1)[0].strip() if parts else ""
    attributes = [segment for segment in parts[1:] if segment]
    return "; ".join([name] + attributes) if name else "; ".join(attributes)


# --- the connect engine ------------------------------------------------------

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
             content_type: str = "") -> tuple:
    """One request to ip, with SNI and Host set to name, returning status and shape.

    Certificate validation is off on purpose, a recon probe records what a server serves, a
    self-signed or mismatched certificate is itself signal, not a reason to skip. The read
    limit is a full document when a caller needs to parse a body such as a spec, and a payload
    turns the request into a POST for a GraphQL introspection.
    """
    if scheme == "https":
        context = ssl.create_default_context()
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
            headers: tuple = ()) -> Liveness:
    match = _TITLE.search(body)
    return Liveness(alive=alive, status=status, url=url, server=server,
                    title=match.group(1).strip()[:200] if match else "", body=body.lower(),
                    location=location, headers=headers, reason="")


def _dead(reason: str = "unreachable") -> Liveness:
    """A not-alive probe result. `reason` tells a genuine negative from a coverage gap.
    `no-public-address` and `refused` are real negatives, `unreachable` is a gap the caller
    records so a host the run never reached is not read as a confirmed dead host."""
    return Liveness(alive=False, reason=reason)

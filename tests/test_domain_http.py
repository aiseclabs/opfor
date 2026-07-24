from __future__ import annotations

import pytest

from opfor.core import Scope
from opfor.scenarios.attacksurface.assets.domain.sources.observations import Resolution

from tests.surface_fixtures import (
    HostScope,
    _run,
    _seed,
)


def test_http_probe_tries_every_public_ip_retries_timeouts_and_raises_the_unexpected(monkeypatch):
    from opfor.scenarios.attacksurface.assets.domain.sources import http as domains

    # the first public address refuses on both schemes, the second answers, so a multi-ip
    # name is alive rather than judged dead on the first unlucky address
    calls = []

    def refuse_first_ip(name, ip, scheme, path, **kw):
        calls.append((ip, scheme))
        if ip == "8.8.8.8":
            raise ConnectionRefusedError()
        return (200, "nginx", "text/html", "<title>ok</title>", "", ())

    monkeypatch.setattr(domains, "_connect", refuse_first_ip)
    result = domains.http_probe("host.example.com", ("8.8.8.8", "1.1.1.1"))
    assert result.alive is True
    assert result.status == 200
    assert ("1.1.1.1", "https") in calls

    # a timeout is transient, so it is retried and the live server on the retry is found
    state = {"n": 0}

    def timeout_then_ok(name, ip, scheme, path, **kw):
        state["n"] += 1
        if state["n"] == 1:
            raise TimeoutError()
        return (200, "nginx", "text/html", "", "", ())

    monkeypatch.setattr(domains, "_connect", timeout_then_ok)
    assert domains.http_probe("host.example.com", ("8.8.8.8",)).alive is True
    assert state["n"] >= 2

    # an unexpected error is raised loud, never passed off as not alive
    def raise_bug(name, ip, scheme, path, **kw):
        raise ValueError("bug")

    monkeypatch.setattr(domains, "_connect", raise_bug)
    with pytest.raises(ValueError):
        domains.http_probe("host.example.com", ("8.8.8.8",))

    # a private-only host has no public address, a real negative, not a coverage gap
    private = domains.http_probe("host.example.com", ("10.0.0.1",))
    assert private.alive is False
    assert private.reason == "no-public-address"

    # a refused connection is evidence there is no web service, a real negative, not a gap
    def refuse_all(name, ip, scheme, path, **kw):
        raise ConnectionRefusedError()

    monkeypatch.setattr(domains, "_connect", refuse_all)
    refused = domains.http_probe("host.example.com", ("8.8.8.8",))
    assert refused.alive is False
    assert refused.reason == "refused"

    # a uniform timeout across every address and scheme means the run could not reach the
    # host, a coverage gap the caller records rather than a confirmed dead host
    def timeout_all(name, ip, scheme, path, **kw):
        raise TimeoutError()

    monkeypatch.setattr(domains, "_connect", timeout_all)
    unreachable = domains.http_probe("host.example.com", ("8.8.8.8", "1.1.1.1"))
    assert unreachable.alive is False
    assert unreachable.reason == "unreachable"

    # the redirect target is captured, so a host fronted by an identity proxy is visible to
    # triage rather than read as a plain live host
    def connect_redirect(name, ip, scheme, path, **kw):
        return (302, "", "text/html", "", "https://accounts.google.com/o/oauth2/v2/auth",
                (("www-authenticate", "Bearer"),))

    monkeypatch.setattr(domains, "_connect", connect_redirect)
    redirected = domains.http_probe("host.example.com", ("8.8.8.8",))
    assert redirected.alive is True
    assert redirected.location == "https://accounts.google.com/o/oauth2/v2/auth"
    assert redirected.headers == (("www-authenticate", "Bearer"),)

def test_http_probe_denied_when_domain_out_of_scope():
    world = _seed()
    report = _run(world, scope=Scope(max_tier="recon", matcher=HostScope(hosts=("other.test",))))
    assert report.closed
    assert not world.has_fact("domain:example.com", "http")
    assert any("denied" in n and "domain_http" in n for n in report.notes)

def test_fetch_url_tries_every_public_address_not_only_the_first(monkeypatch):
    # a host whose first address is dead but second is live must still be enriched, so the
    # fetch seam iterates all public addresses the way the alive probe does
    from opfor.scenarios.attacksurface.assets.domain.sources import http as domains
    seen = []

    def connect(name, ip, scheme, path, **kw):
        seen.append(ip)
        if ip == "1.1.1.1":
            raise TimeoutError("dead first address")
        return (200, "nginx", "text/html", "<title>ok</title>", "", ())

    monkeypatch.setattr(domains, "_connect", connect)
    result = domains.fetch_url("h.example.com", ("1.1.1.1", "2.2.2.2"), "/x")
    assert result.status == 200 and "2.2.2.2" in seen

def test_fetch_seams_are_loud_on_the_unexpected_and_name_why_no_address_answered(monkeypatch):
    from opfor.scenarios.attacksurface.assets.domain.sources import http as domains

    # every fetch seam shares the alive probe's contract: only a transport error is caught and
    # continued past, an unexpected error is raised loud rather than swallowed as a null status.
    def raise_bug(name, ip, scheme, path, **kw):
        raise ValueError("bug")

    monkeypatch.setattr(domains, "_connect", raise_bug)
    monkeypatch.setattr(domains, "resolve_host", lambda n: Resolution(resolvable=True, addresses=("2.2.2.2",)))
    with pytest.raises(ValueError):
        domains.fetch_url("h.example.com", ("2.2.2.2",), "/x")
    with pytest.raises(ValueError):
        domains.fetch_document("h.example.com", "/x")
    with pytest.raises(ValueError):
        domains.fetch_readonly("https://h.example.com/x")

    # a transport error on every address is not a real absent path, it is a coverage gap, so
    # the null status names the reason rather than leaving the caller to guess at a bare null
    def timeout_all(name, ip, scheme, path, **kw):
        raise TimeoutError()

    monkeypatch.setattr(domains, "_connect", timeout_all)
    assert domains.fetch_url("h.example.com", ("2.2.2.2",), "/x").reason == "unreachable"
    assert domains.fetch_document("h.example.com", "/x").reason == "unreachable"
    assert domains.fetch_readonly("https://h.example.com/x").reason == "unreachable"

    # a host with no public address is told apart from a host that had one but did not answer
    monkeypatch.setattr(domains, "resolve_host", lambda n: Resolution(resolvable=True, addresses=("10.0.0.1",)))
    assert domains.fetch_url("h.example.com", ("10.0.0.1",), "/x").reason == "no-public-address"
    assert domains.fetch_document("h.example.com", "/x").reason == "no-public-address"
    assert domains.fetch_readonly("https://h.example.com/x").reason == "no-public-address"

def test_readonly_fetch_refuses_a_host_that_resolves_only_to_a_private_address(monkeypatch):
    from opfor.scenarios.attacksurface.assets.domain.sources import http as domains
    monkeypatch.setattr(domains, "resolve_host",
                        lambda h: Resolution(resolvable=True, addresses=("127.0.0.1",), cnames=()))
    # a name repointed at loopback between observation and replay must not be fetched
    assert domains.fetch_readonly("http://internal.example.com/x").status is None

def test_readonly_fetch_pins_a_public_address_and_verifies_the_certificate(monkeypatch):
    from opfor.scenarios.attacksurface.assets.domain.sources import http as domains
    monkeypatch.setattr(domains, "resolve_host",
                        lambda h: Resolution(resolvable=True, addresses=("93.184.216.34",), cnames=()))
    seen = {}

    def fake_connect(name, ip, scheme, path, **kw):
        seen["ip"] = ip
        seen["verify"] = kw.get("verify")
        return (200, "s", "text/html", "body", "", ())

    monkeypatch.setattr(domains, "_connect", fake_connect)
    result = domains.fetch_readonly("https://example.com/panel")
    # the replay is pinned to the vetted public address and verifies the certificate
    assert result.status == 200 and seen["ip"] == "93.184.216.34" and seen["verify"] is True

def test_connect_closes_the_raw_socket_when_the_tls_handshake_fails(monkeypatch):
    import socket
    import ssl

    from opfor.scenarios.attacksurface.assets.domain.sources import http as domains

    closed = {"n": 0}

    class _Raw:
        def close(self):
            closed["n"] += 1

    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: _Raw())

    def boom(self, sock, server_hostname=None):
        raise ssl.SSLError("handshake failed")

    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", boom)
    # a host with 443 open but not speaking TLS must not leak the raw socket, else a scan
    # exhausts the file-descriptor limit
    with pytest.raises(ssl.SSLError):
        domains._connect("h", "1.2.3.4", "https", "/")
    assert closed["n"] == 1

def test_read_capped_stops_at_the_wall_clock_deadline(monkeypatch):
    from opfor.scenarios.attacksurface.assets.domain.sources import http as domains
    clock = {"t": 0.0}
    monkeypatch.setattr(domains.time, "monotonic", lambda: clock["t"])

    class _Drip:
        def read1(self, n):
            clock["t"] += 20.0   # each read advances past the 30s deadline within two reads
            return b"x"

    body = domains._read_capped(_Drip(), read_limit=1000)
    # a slow-drip response is cut off at the deadline instead of tying the worker for 1000 bytes
    assert 0 < len(body) < 1000

def test_signal_headers_keeps_identity_drops_noise_and_masks_cookie_value():
    from opfor.scenarios.attacksurface.assets.domain.sources import http as domains

    class _Resp:
        def getheaders(self):
            return [("Server", "nginx"), ("Date", "Mon"), ("Content-Length", "10"),
                    ("X-Powered-By", "Express"), ("WWW-Authenticate", "Bearer realm=x"),
                    ("Set-Cookie", "_gitlab_session=secretvalue; Path=/")]

    hdrs = dict(domains._signal_headers(_Resp()))
    # identity headers are kept, noise is dropped
    assert hdrs["x-powered-by"] == "Express"
    assert hdrs["www-authenticate"] == "Bearer realm=x"
    assert hdrs["server"] == "nginx"
    assert "date" not in hdrs and "content-length" not in hdrs
    # a cookie keeps its name and attributes so the flags stay visible, but the value is a
    # secret and is dropped
    assert hdrs["set-cookie"] == "_gitlab_session; Path=/"
    assert "secretvalue" not in hdrs["set-cookie"]

def test_signal_headers_capture_security_headers_complete_past_the_identification_cap():
    from opfor.scenarios.attacksurface.assets.domain.sources import http as domains

    # a wall of non-security headers beyond the identification cap, with the security family
    # arriving last, so a naive cap would drop them and triage could not tell absent from cut
    noise = [(f"x-app-{i}", "v") for i in range(40)]
    headers = noise + [("Strict-Transport-Security", "max-age=63072000"),
                       ("Content-Security-Policy", "default-src 'self'"),
                       ("X-Frame-Options", "DENY")]

    class Resp:
        def getheaders(self):
            return headers

    captured = dict(domains._signal_headers(Resp()))
    # HSTS and CSP are no longer dropped as noise, and every security header survives the cap
    assert captured["strict-transport-security"] == "max-age=63072000"
    assert captured["content-security-policy"] == "default-src 'self'"
    assert captured["x-frame-options"] == "DENY"

def test_signal_headers_keep_cookie_flags_but_drop_the_secret_value():
    from opfor.scenarios.attacksurface.assets.domain.sources import http as domains

    class Resp:
        def getheaders(self):
            return [("Set-Cookie", "sid=SECRETVALUE; Path=/; Secure; HttpOnly; SameSite=Lax"),
                    ("Set-Cookie", "tracker=xyztoken")]

    cookies = [v for n, v in domains._signal_headers(Resp()) if n == "set-cookie"]
    # the flags survive so triage can judge them, but the secret value never enters the report
    assert "sid; Path=/; Secure; HttpOnly; SameSite=Lax" in cookies
    assert "tracker" in cookies
    assert all("SECRETVALUE" not in v and "xyztoken" not in v for v in cookies)

def test_graphql_introspection_raises_on_a_server_error(monkeypatch):
    from opfor.scenarios.attacksurface.assets.domain.sources import http as domains
    monkeypatch.setattr(domains, "resolve_host", lambda n: Resolution(resolvable=True, addresses=("2.2.2.2",)))
    monkeypatch.setattr(domains, "_connect", lambda *a, **k: (500, "", "", "", "", ()))
    # a 5xx introspection is errored and unknown, never reported as safely disabled
    with pytest.raises(RuntimeError):
        domains.graphql_introspect("h.example.com", "/graphql")

def test_graphql_introspection_is_off_on_a_client_refusal(monkeypatch):
    from opfor.scenarios.attacksurface.assets.domain.sources import http as domains
    monkeypatch.setattr(domains, "resolve_host", lambda n: Resolution(resolvable=True, addresses=("2.2.2.2",)))
    monkeypatch.setattr(domains, "_connect",
                        lambda *a, **k: (403, "", "", "introspection disabled", "", ()))
    # a 4xx is an intentional refusal, a genuine off, so None rather than a raise
    assert domains.graphql_introspect("h.example.com", "/graphql") is None

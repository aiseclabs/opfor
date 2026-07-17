from __future__ import annotations

import json

import pytest

from opfor.core import Scope

from tests.surface_fixtures import *


def test_resolve_host_keeps_cname_and_asks_both_address_families(monkeypatch):
    import urllib.request

    from opfor.scenarios.attacksurface.assets.domain import sources as domains

    asked = []

    class _Resp:
        def __init__(self, payload):
            self._payload = payload

        def read(self, *_a):
            return json.dumps(self._payload).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    # a CNAME to an unclaimed target, answered but with no address, is the dangling case
    def fake_urlopen(request, timeout=0):
        asked.append(request.full_url)
        if "type=A" in request.full_url:
            return _Resp({"Answer": [{"type": 5, "data": "target.s3.amazonaws.com."}]})
        return _Resp({"Answer": []})

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    result = domains.resolve_host("dangling.example.com")
    assert result["resolvable"] is False
    assert result["addresses"] == ()
    assert result["cnames"] == ("target.s3.amazonaws.com",)
    assert any("type=A" in u for u in asked) and any("type=AAAA" in u for u in asked)

def test_resolve_host_treats_a_servfail_as_a_resolver_error_not_a_no_address(monkeypatch):
    import urllib.request

    from opfor.scenarios.attacksurface.assets.domain.sources import http as domains

    class _Resp:
        def __init__(self, payload):
            self._payload = payload

        def read(self, *_a):
            return json.dumps(self._payload).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    calls = {"n": 0}

    def fake_urlopen(request, timeout=0):
        calls["n"] += 1
        # the first resolver SERVFAILs on both A and AAAA, the second answers with an address
        if calls["n"] <= 2:
            return _Resp({"Status": 2, "Answer": []})
        return _Resp({"Status": 0, "Answer": [{"type": 1, "data": "1.2.3.4"}]})

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    result = domains.resolve_host("h.example.com")
    # a SERVFAIL is not accepted as a confirmed no-address, the next resolver is consulted
    assert result["resolvable"] is True and "1.2.3.4" in result["addresses"]
    assert calls["n"] >= 3

def test_doh_lookup_fails_over_resolvers_and_raises_when_all_error(monkeypatch):
    from opfor.scenarios.attacksurface.assets.domain.sources import dns as domains

    tried = []

    def records(resolver, name, rtype):
        tried.append(resolver)
        return (2, [], False)  # SERVFAIL on every resolver, a resolver error not a real answer

    monkeypatch.setattr(domains, "_doh_records", records)
    with pytest.raises(RuntimeError):
        domains._doh_lookup("example.com", "TXT")
    # every resolver was tried before the failure was raised, so one flaky resolver does not blind it
    assert len(tried) == len(domains._DOH_RESOLVERS)

def test_dns_email_posture_reads_spf_dmarc_caa_and_dnssec(monkeypatch):
    from opfor.scenarios.attacksurface.assets.domain.sources import dns as domains

    def lookup(name, rtype):
        if name == "example.com" and rtype == "TXT":
            # the ad flag on the domain lookup is the DNSSEC signal, and a non-spf TXT is ignored
            return ([{"type": 16, "data": '"v=spf1 include:_spf.example.com -all"'},
                     {"type": 16, "data": '"google-site-verification=abc"'}], True)
        if name == "_dmarc.example.com" and rtype == "TXT":
            return ([{"type": 16, "data": '"v=DMARC1; p=reject"'}], False)
        if name == "example.com" and rtype == "CAA":
            return ([{"type": 257, "data": '0 issue "letsencrypt.org"'}], False)
        raise AssertionError((name, rtype))

    monkeypatch.setattr(domains, "_doh_lookup", lookup)
    posture = domains.dns_email_posture("example.com")
    assert posture["spf"] == ("v=spf1 include:_spf.example.com -all",)
    assert posture["dmarc"] == "v=DMARC1; p=reject"
    assert posture["caa"] == ('0 issue "letsencrypt.org"',)
    assert posture["dnssec"] is True

def test_dns_email_capability_reports_records_and_fails_loud_on_error():
    from opfor.core import Done, Failed, Node, Task, World
    from opfor.scenarios.attacksurface.assets.domain.capabilities.dns import DNSEmailSecurity
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData

    world = World()
    world.add(Node(id="domain:example.com", type="domain",
                   payload=DomainData(name="example.com", root="example.com", source="hint")))
    task = Task(capability="dns_email", node="domain:example.com")

    ok = DNSEmailSecurity(lambda d: {"spf": ("v=spf1 -all",), "dmarc": "", "caa": (), "dnssec": True})
    out = ok.run(task, world)
    assert isinstance(out, Done)
    assert out.facts[0].payload.spf == ("v=spf1 -all",)
    assert out.facts[0].payload.dnssec is True

    def boom(domain):
        raise RuntimeError("dns down")

    # a lookup that fails is a loud Failed, never a silent clean absence of records
    assert isinstance(DNSEmailSecurity(boom).run(task, world), Failed)

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
    assert result["alive"] is True
    assert result["status"] == 200
    assert ("1.1.1.1", "https") in calls

    # a timeout is transient, so it is retried and the live server on the retry is found
    state = {"n": 0}

    def timeout_then_ok(name, ip, scheme, path, **kw):
        state["n"] += 1
        if state["n"] == 1:
            raise TimeoutError()
        return (200, "nginx", "text/html", "", "", ())

    monkeypatch.setattr(domains, "_connect", timeout_then_ok)
    assert domains.http_probe("host.example.com", ("8.8.8.8",))["alive"] is True
    assert state["n"] >= 2

    # an unexpected error is raised loud, never passed off as not alive
    def raise_bug(name, ip, scheme, path, **kw):
        raise ValueError("bug")

    monkeypatch.setattr(domains, "_connect", raise_bug)
    with pytest.raises(ValueError):
        domains.http_probe("host.example.com", ("8.8.8.8",))

    # a private-only host has no public address, a real negative, not a coverage gap
    private = domains.http_probe("host.example.com", ("10.0.0.1",))
    assert private["alive"] is False
    assert private["reason"] == "no-public-address"

    # a refused connection is evidence there is no web service, a real negative, not a gap
    def refuse_all(name, ip, scheme, path, **kw):
        raise ConnectionRefusedError()

    monkeypatch.setattr(domains, "_connect", refuse_all)
    refused = domains.http_probe("host.example.com", ("8.8.8.8",))
    assert refused["alive"] is False
    assert refused["reason"] == "refused"

    # a uniform timeout across every address and scheme means the run could not reach the
    # host, a coverage gap the caller records rather than a confirmed dead host
    def timeout_all(name, ip, scheme, path, **kw):
        raise TimeoutError()

    monkeypatch.setattr(domains, "_connect", timeout_all)
    unreachable = domains.http_probe("host.example.com", ("8.8.8.8", "1.1.1.1"))
    assert unreachable["alive"] is False
    assert unreachable["reason"] == "unreachable"

    # the redirect target is captured, so a host fronted by an identity proxy is visible to
    # triage rather than read as a plain live host
    def connect_redirect(name, ip, scheme, path, **kw):
        return (302, "", "text/html", "", "https://accounts.google.com/o/oauth2/v2/auth",
                (("www-authenticate", "Bearer"),))

    monkeypatch.setattr(domains, "_connect", connect_redirect)
    redirected = domains.http_probe("host.example.com", ("8.8.8.8",))
    assert redirected["alive"] is True
    assert redirected["location"] == "https://accounts.google.com/o/oauth2/v2/auth"
    assert redirected["headers"] == (("www-authenticate", "Bearer"),)

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
    assert result["status"] == 200 and "2.2.2.2" in seen

def test_fetch_seams_are_loud_on_the_unexpected_and_name_why_no_address_answered(monkeypatch):
    from opfor.scenarios.attacksurface.assets.domain.sources import http as domains

    # every fetch seam shares the alive probe's contract: only a transport error is caught and
    # continued past, an unexpected error is raised loud rather than swallowed as a null status.
    def raise_bug(name, ip, scheme, path, **kw):
        raise ValueError("bug")

    monkeypatch.setattr(domains, "_connect", raise_bug)
    monkeypatch.setattr(domains, "resolve_host", lambda n: {"addresses": ("2.2.2.2",)})
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
    assert domains.fetch_url("h.example.com", ("2.2.2.2",), "/x")["reason"] == "unreachable"
    assert domains.fetch_document("h.example.com", "/x")["reason"] == "unreachable"
    assert domains.fetch_readonly("https://h.example.com/x")["reason"] == "unreachable"

    # a host with no public address is told apart from a host that had one but did not answer
    monkeypatch.setattr(domains, "resolve_host", lambda n: {"addresses": ("10.0.0.1",)})
    assert domains.fetch_url("h.example.com", ("10.0.0.1",), "/x")["reason"] == "no-public-address"
    assert domains.fetch_document("h.example.com", "/x")["reason"] == "no-public-address"
    assert domains.fetch_readonly("https://h.example.com/x")["reason"] == "no-public-address"

def test_fetch_public_url_is_loud_on_the_unexpected_and_names_unreachable(monkeypatch):
    from opfor.scenarios.attacksurface.assets.domain.sources import http as domains

    # the host resolves to a public address, so it clears the no-private-address guard and the
    # opener behavior below is what is under test
    monkeypatch.setattr(domains, "resolve_host", lambda n: {"addresses": ("1.1.1.1",)})

    class BugOpener:
        def open(self, *a, **k):
            raise ValueError("bug")

    monkeypatch.setattr(domains, "_NO_REDIRECT_OPENER", BugOpener())
    with pytest.raises(ValueError):
        domains.fetch_public_url("https://bucket.example.com/")

    class DeadOpener:
        def open(self, *a, **k):
            raise ConnectionResetError()

    monkeypatch.setattr(domains, "_NO_REDIRECT_OPENER", DeadOpener())
    assert domains.fetch_public_url("https://bucket.example.com/")["reason"] == "unreachable"

def test_fetch_public_url_uses_the_no_redirect_opener(monkeypatch):
    from opfor.scenarios.attacksurface.assets.domain.sources import http as domains

    used = {}

    class _Resp:
        status = 200
        headers = {"Content-Type": "application/xml"}

        def read(self, *_a):
            return b"<ListBucketResult/>"

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_open(req, timeout=0):
        used["opener"] = True
        return _Resp()

    monkeypatch.setattr(domains._NO_REDIRECT_OPENER, "open", fake_open)
    result = domains.fetch_public_url("https://x.s3.amazonaws.com/")
    # a bucket probe does not chase a server-controlled redirect off to another host
    assert used.get("opener") and result["status"] == 200

def test_readonly_fetch_refuses_a_host_that_resolves_only_to_a_private_address(monkeypatch):
    from opfor.scenarios.attacksurface.assets.domain.sources import http as domains
    monkeypatch.setattr(domains, "resolve_host",
                        lambda h: {"addresses": ("127.0.0.1",), "resolvable": True, "cnames": ()})
    # a name repointed at loopback between observation and replay must not be fetched
    assert domains.fetch_readonly("http://internal.example.com/x")["status"] is None

def test_readonly_fetch_pins_a_public_address_and_verifies_the_certificate(monkeypatch):
    from opfor.scenarios.attacksurface.assets.domain.sources import http as domains
    monkeypatch.setattr(domains, "resolve_host",
                        lambda h: {"addresses": ("93.184.216.34",), "resolvable": True, "cnames": ()})
    seen = {}

    def fake_connect(name, ip, scheme, path, **kw):
        seen["ip"] = ip
        seen["verify"] = kw.get("verify")
        return (200, "s", "text/html", "body", "", ())

    monkeypatch.setattr(domains, "_connect", fake_connect)
    result = domains.fetch_readonly("https://example.com/panel")
    # the replay is pinned to the vetted public address and verifies the certificate
    assert result["status"] == 200 and seen["ip"] == "93.184.216.34" and seen["verify"] is True

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
    monkeypatch.setattr(domains, "resolve_host", lambda n: {"addresses": ("2.2.2.2",)})
    monkeypatch.setattr(domains, "_connect", lambda *a, **k: (500, "", "", "", "", ()))
    # a 5xx introspection is errored and unknown, never reported as safely disabled
    with pytest.raises(RuntimeError):
        domains.graphql_introspect("h.example.com", "/graphql")

def test_graphql_introspection_is_off_on_a_client_refusal(monkeypatch):
    from opfor.scenarios.attacksurface.assets.domain.sources import http as domains
    monkeypatch.setattr(domains, "resolve_host", lambda n: {"addresses": ("2.2.2.2",)})
    monkeypatch.setattr(domains, "_connect",
                        lambda *a, **k: (403, "", "", "introspection disabled", "", ()))
    # a 4xx is an intentional refusal, a genuine off, so None rather than a raise
    assert domains.graphql_introspect("h.example.com", "/graphql") is None

def test_tls_probe_reports_a_valid_certificate_with_its_expiry(monkeypatch):
    from opfor.scenarios.attacksurface.assets.domain.sources import tls as domains

    def connect(name, ip, context):
        return ({"notAfter": "Jun  1 12:00:00 2099 GMT"}, "TLSv1.3",
                ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256))

    monkeypatch.setattr(domains, "_tls_connect", connect)
    out = domains.tls_probe("h.example.com", ("1.2.3.4",))
    assert out["reachable"] and out["valid"]
    assert out["protocol"] == "TLSv1.3"
    assert out["days_to_expiry"] > 0

def test_tls_probe_reports_an_untrusted_certificate_as_reachable_but_invalid(monkeypatch):
    import ssl
    from opfor.scenarios.attacksurface.assets.domain.sources import tls as domains

    def connect(name, ip, context):
        # the verifying context raises on a bad cert, the unverified reconnect still reads the
        # protocol, so a reached host with a bad certificate is not mistaken for unreachable
        if context.verify_mode == ssl.CERT_REQUIRED:
            err = ssl.SSLCertVerificationError("self-signed certificate in certificate chain")
            err.verify_message = "self-signed certificate in certificate chain"
            raise err
        return ({}, "TLSv1.2", ("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2", 128))

    monkeypatch.setattr(domains, "_tls_connect", connect)
    out = domains.tls_probe("h.example.com", ("1.2.3.4",))
    assert out["reachable"] and not out["valid"]
    assert "self-signed" in out["validity_error"]
    assert out["protocol"] == "TLSv1.2"

def test_tls_probe_is_a_clean_not_reachable_when_the_port_does_not_answer(monkeypatch):
    from opfor.scenarios.attacksurface.assets.domain.sources import tls as domains

    assert domains.tls_probe("h.example.com", ("10.0.0.1",))["reason"] == "no-public-address"

    def refuse(name, ip, context):
        raise OSError("connection refused")

    monkeypatch.setattr(domains, "_tls_connect", refuse)
    out = domains.tls_probe("h.example.com", ("1.2.3.4",))
    assert out["reachable"] is False

def test_tls_capability_reports_posture_and_fails_loud_on_error():
    from opfor.core import Done, Failed, Node, Task, World
    from opfor.scenarios.attacksurface.assets.domain.capabilities.tls import TLSSecurity
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData

    world = World()
    world.add(Node(id="domain:h.example.com", type="domain",
                   payload=DomainData(name="h.example.com", root="example.com", source="hint")))
    task = Task(capability="tls", node="domain:h.example.com", scope_target="h.example.com")

    ok = TLSSecurity(lambda n, a: {"reachable": True, "valid": False,
                                   "validity_error": "certificate has expired"})
    out = ok.run(task, world)
    assert isinstance(out, Done)
    assert out.facts[0].payload.valid is False
    assert "expired" in out.facts[0].payload.validity_error

    def boom(name, addresses):
        raise RuntimeError("tls down")

    assert isinstance(TLSSecurity(boom).run(task, world), Failed)

def test_port_scan_reports_open_service_ports_with_banners(monkeypatch):
    from opfor.scenarios.attacksurface.assets.domain.sources import ports as domains

    opened = {22: "SSH-2.0-OpenSSH_8.9", 6379: ""}  # ssh answers a banner, redis is open silently

    def probe(ip, port):
        return opened.get(port)  # None means closed or filtered

    monkeypatch.setattr(domains, "_probe_port", probe)
    out = domains.port_scan("h.example.com", ("1.2.3.4",))
    assert out["reachable"] and out["scanned"] == len(domains._SERVICE_PORTS)
    ports = {p["port"]: p for p in out["open"]}
    assert ports[22]["service"] == "ssh" and "OpenSSH" in ports[22]["banner"]
    assert 6379 in ports and ports[6379]["service"] == "redis"
    # a closed port is not reported, so an absent port is a real closed-or-filtered negative
    assert 3389 not in ports

def test_port_scan_is_not_reachable_without_a_public_address():
    from opfor.scenarios.attacksurface.assets.domain.sources import ports as domains

    out = domains.port_scan("h.example.com", ("10.0.0.1",))
    assert out["reachable"] is False and out["reason"] == "no-public-address"

def test_port_scan_capability_is_probe_tier_and_packs_facts_and_fails_loud():
    from opfor.core import Done, Failed, Node, Task, World
    from opfor.scenarios.attacksurface.assets.domain.capabilities.ports import PortServices
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData

    # the scan touches the target's ports, above recon, so it is a probe-tier act scope gates
    assert PortServices(lambda n, a: {}).tier == "probe"

    world = World()
    world.add(Node(id="domain:h.example.com", type="domain",
                   payload=DomainData(name="h.example.com", root="example.com", source="hint")))
    task = Task(capability="port_scan", node="domain:h.example.com", scope_target="h.example.com")

    ok = PortServices(lambda n, a: {"reachable": True, "scanned": 24,
                                    "open": [{"port": 6379, "service": "redis", "banner": ""}]})
    out = ok.run(task, world)
    assert isinstance(out, Done)
    assert out.facts[0].payload.open_ports[0].port == 6379

    def boom(name, addresses):
        raise RuntimeError("scan down")

    assert isinstance(PortServices(boom).run(task, world), Failed)

def test_registrable_root_keeps_multi_label_suffixes():
    from opfor.scenarios.attacksurface.hostnames import registrable_root

    assert registrable_root("api.example.com") == "example.com"
    assert registrable_root("example.com") == "example.com"
    assert registrable_root("a.b.example.co.uk") == "example.co.uk"

def test_registrable_root_recognizes_country_second_levels_generally():
    from opfor.scenarios.attacksurface.hostnames import registrable_root
    # an uncurated country suffix is no longer mis-rooted, com.ph and co.nz keep three labels
    assert registrable_root("api.company.com.ph") == "company.com.ph"
    assert registrable_root("www.shop.co.nz") == "shop.co.nz"
    # the curated and default cases are unchanged
    assert registrable_root("host.example.co.uk") == "example.co.uk"
    assert registrable_root("a.b.example.com") == "example.com"
    assert registrable_root("api.example.com") == "example.com"

def test_registrable_root_leaves_an_ip_literal_unchanged():
    from opfor.scenarios.attacksurface.hostnames import registrable_root
    # an IP has no registrable root, folding it to the last two octets would mint a bogus root
    assert registrable_root("10.0.0.5") == "10.0.0.5"
    assert registrable_root("192.168.1.1") == "192.168.1.1"

def test_same_host_path_matches_a_mixed_case_host():
    from opfor.scenarios.attacksurface.assets.domain.sources.parsers import same_host_path
    # a mixed-case host name must still match its own absolute urls, else script and sitemap
    # extraction drop every same-host link
    assert same_host_path("https://Example.com/app.js", "Example.com") == "/app.js"

def test_operator_hint_domain_is_lowercased_into_a_canonical_node():
    from opfor.core import Node, Task, World
    from opfor.scenarios.attacksurface.assets.domain.capabilities.discovery import DiscoverDomains
    from opfor.scenarios.attacksurface.types import Org

    world = World()
    world.add(Node(id="org:x", type="org", payload=Org(name="X", domains=("Example.COM",))))
    outcome = DiscoverDomains().run(Task(capability="discover_domains", node="org:x"), world)
    ids = {n.id for n in outcome.facts[0].yields}
    assert "domain:example.com" in ids

def test_looks_like_host_rejects_a_slash_label_and_keeps_a_wildcard():
    from opfor.scenarios.attacksurface.hostnames import looks_like_host

    assert looks_like_host("api.example.com") is True
    assert looks_like_host("*.dev.example.com") is True
    # a cert SAN or DNS export value with a slash must not be admitted as a host node
    assert looks_like_host("evil.com/x.example.com") is False
    assert looks_like_host("a b.example.com") is False
    assert looks_like_host("user@example.com") is False


def test_host_scope_admits_a_host_and_its_subdomains_but_pins_the_dot_boundary():
    scope = HostScope(hosts=("example.com",))
    assert scope.in_scope("example.com")
    assert scope.in_scope("api.example.com")
    # a subdomain matches through the dot boundary, but a look-alike sibling never does
    assert not scope.in_scope("evilexample.com")
    assert not scope.in_scope("other.test")


def test_host_scope_normalizes_case_and_a_trailing_root_dot():
    scope = HostScope(hosts=("Example.COM.",))
    assert scope.in_scope("API.example.com")
    assert scope.in_scope("example.com.")


def test_host_scope_admits_an_exact_resource_and_drops_a_blank_host():
    scope = HostScope(hosts=("", "   ", "."), resources=("repo:owner/name",))
    # a blank or bare-dot host normalizes away, so nothing rides the suffix rule
    assert not scope.in_scope("anything.com")
    assert scope.in_scope("repo:owner/name")
    assert not scope.in_scope("repo:other/name")


def test_host_scope_round_trips_through_its_dict():
    scope = HostScope(hosts=("example.com",), resources=("repo:o/n",))
    revived = HostScope.from_dict(scope.to_dict())
    assert revived.in_scope("api.example.com") and revived.in_scope("repo:o/n")


def test_host_scope_drops_a_blank_resource_so_a_blank_target_is_never_in_scope():
    scope = HostScope(hosts=("example.com",), resources=("", "   ", "repo:o/n"))
    assert not scope.in_scope("")
    assert not scope.in_scope("   ")
    assert scope.in_scope("repo:o/n")


def test_host_scope_does_not_let_a_resource_shaped_target_ride_the_suffix_rule():
    scope = HostScope(hosts=("example.com",))
    # a resource id ending in .<in-scope-host> must not match through the host suffix rule
    assert not scope.in_scope("repo:owner/deploy.example.com")
    # a genuine subdomain still matches
    assert scope.in_scope("deploy.example.com")


def test_host_scope_gates_end_to_end_through_scope_authorize():
    # the scenario matcher wired into the kernel Scope: an out-of-scope host is denied and a
    # subdomain of an in-scope host is allowed, all the way through authorize
    scope = Scope(max_tier="recon", matcher=HostScope(hosts=("example.com",)))
    assert not scope.authorize("recon", osint=False, target="evil.test").allowed
    assert scope.authorize("recon", osint=False, target="api.example.com").allowed

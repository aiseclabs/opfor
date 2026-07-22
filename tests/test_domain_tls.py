from __future__ import annotations


def test_tls_probe_reports_a_valid_certificate_with_its_expiry(monkeypatch):
    from opfor.scenarios.attacksurface.assets.domain.sources import tls as domains

    def connect(name, ip, context):
        return ({"notAfter": "Jun  1 12:00:00 2099 GMT"}, b"", "TLSv1.3",
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
        if context.check_hostname:
            err = ssl.SSLCertVerificationError("self-signed certificate in certificate chain")
            err.verify_message = "self-signed certificate in certificate chain"
            raise err
        # the unverified reconnect returns an empty der, so the leaf-trust recovery no-ops here
        return ({}, b"", "TLSv1.2", ("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2", 128))

    monkeypatch.setattr(domains, "_tls_connect", connect)
    out = domains.tls_probe("h.example.com", ("1.2.3.4",))
    assert out["reachable"] and not out["valid"]
    assert "self-signed" in out["validity_error"]
    assert out["protocol"] == "TLSv1.2"

def test_tls_probe_recovers_expiry_for_an_invalid_certificate(monkeypatch):
    import ssl
    from opfor.scenarios.attacksurface.assets.domain.sources import tls as domains

    def connect(name, ip, context):
        # the initial verifying handshake (check_hostname on) fails on a mismatched cert
        if context.check_hostname:
            err = ssl.SSLCertVerificationError("hostname mismatch")
            err.verify_message = "hostname mismatch"
            raise err
        return ({}, b"DER", "TLSv1.2", ("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2", 128))

    monkeypatch.setattr(domains, "_tls_connect", connect)
    # the leaf-trust recovery reads the date the CERT_NONE dict lacks
    monkeypatch.setattr(domains, "_validity_of",
                        lambda n, ip, der: {"notAfter": "Jun  1 12:00:00 2099 GMT"})
    out = domains.tls_probe("h.example.com", ("1.2.3.4",))
    # invalid, yet its expiry is recovered rather than left silently blank
    assert not out["valid"]
    assert out["days_to_expiry"] > 0

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

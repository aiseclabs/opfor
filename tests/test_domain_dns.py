from __future__ import annotations

import json


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
    assert result.resolvable is False
    assert result.addresses == ()
    assert result.cnames == ("target.s3.amazonaws.com",)
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
    assert result.resolvable is True and "1.2.3.4" in result.addresses
    assert calls["n"] >= 3

def test_resolve_host_does_not_launder_a_mixed_rcode_into_a_no_address(monkeypatch):
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
        # first resolver: A SERVFAILs (rcode 2) while AAAA answers NOERROR-empty (rcode 0). The
        # A absence is unproven, so this must not read as a confirmed no-address, it must fail over.
        if calls["n"] == 1:
            return _Resp({"Status": 2, "Answer": []})   # r1 A: SERVFAIL
        if calls["n"] == 2:
            return _Resp({"Status": 0, "Answer": []})   # r1 AAAA: NOERROR, empty
        return _Resp({"Status": 0, "Answer": [{"type": 1, "data": "1.2.3.4"}]})  # r2 answers

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    result = domains.resolve_host("h.example.com")
    # the mixed rcode is a resolver error on the A family, not a proven no-address, so failover ran
    assert result.resolvable is True and "1.2.3.4" in result.addresses
    assert calls["n"] >= 3

from __future__ import annotations

import json

import pytest

from opfor.core import Budget, Scope, run

from tests.surface_fixtures import *


def test_hosts_from_file_normalizes_a_dns_export(tmp_path):
    from opfor.scenarios.attacksurface.assets.domain.sources import hosts_from_file

    export = tmp_path / "dns.txt"
    export.write_text(
        "# a dns export\n"
        "\n"
        "api.dev.example.com\n"
        "*.sandbox.example.com\n"                                  # wildcard base is a real host
        "_0007c31f57915f7fdc0b0f3de4b50248.api.hodor.example.com\n"  # ACM record wraps a host
        "sel._domainkey.example.com\n"                            # DKIM control record, dropped
        "API.DEV.EXAMPLE.COM\n",                                  # duplicate after lowercasing
        encoding="utf-8")
    hosts = hosts_from_file(str(export))
    assert hosts == ("api.dev.example.com", "api.hodor.example.com", "sandbox.example.com")

def test_cert_san_pivot_discovers_a_sibling_root_with_evidence():
    world = _seed()
    _run(world)
    net = world.node("domain:example.net")
    assert net is not None
    assert net.payload.root == "example.net"
    assert net.payload.source == "cert-san"
    # cert co-tenancy is weaker evidence than a registration match, so a cert-SAN sibling is
    # associated, not confirmed, and triage sees the lower confidence
    assert net.payload.confidence == "associated"
    assert "shares a certificate" in net.payload.evidence

def test_discovered_root_is_an_info_finding_carrying_its_evidence():
    report = _run(_seed())
    roots = [f for f in report.findings if f.data.get("kind") == "root"]
    assert [f.where for f in roots] == ["example.net"]
    assert roots[0].severity == "INFO"
    assert "shares a certificate" in roots[0].evidence

def test_hint_root_is_not_reported_as_a_discovered_root():
    report = _run(_seed())
    assert "example.com" not in {f.where for f in report.findings if f.data.get("kind") == "root"}

def test_shared_certificate_is_not_treated_as_ownership_evidence():
    from opfor.scenarios.attacksurface.assets.domain.sources import sibling_roots_from_issuances

    # a dedicated cert bundling two roots yields the sibling
    dedicated = [{"dns_names": ["example.com", "www.example.net"]}]
    assert sibling_roots_from_issuances(dedicated, "example.com") == {
        "example.net": "shares a certificate with example.com, 2 roots on the cert"
    }
    # a multi-tenant cert bundling many unrelated roots proves nothing, so it is skipped
    shared = [{"dns_names": ["example.com", "a.org", "b.org", "c.org", "d.org", "e.org", "f.org"]}]
    assert sibling_roots_from_issuances(shared, "example.com") == {}

def test_cert_sibling_pivot_walks_past_the_first_page(monkeypatch):
    import urllib.request

    from opfor.scenarios.attacksurface import config
    from opfor.scenarios.attacksurface.assets.domain import sources as domains

    monkeypatch.setattr(config, "certspotter_token", lambda: None)

    class _Resp:
        def __init__(self, payload):
            self._payload = payload

        def read(self, *_a):
            return json.dumps(self._payload).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    # page one holds only the seed's own cert, the sibling rides a cert reached only once
    # the walk follows the `after` cursor to the next page, so a single-page fetch misses it
    pages = {
        "": [{"id": "1", "dns_names": ["example.com"]}],
        "1": [{"id": "2", "dns_names": ["example.com", "example.net"]}],
    }

    def fake_urlopen(request, timeout=0):
        after = request.full_url.split("after=")[1] if "after=" in request.full_url else ""
        return _Resp(pages.get(after, []))

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    assert domains.cert_sibling_roots("example.com") == {
        "example.net": "shares a certificate with example.com, 2 roots on the cert"
    }

def test_virustotal_enumeration_flags_truncation_at_the_page_cap(monkeypatch):
    import urllib.request

    from opfor.scenarios.attacksurface import config
    from opfor.scenarios.attacksurface.assets.domain import sources as domains

    monkeypatch.setattr(config, "virustotal_key", lambda: "vt")

    class _Resp:
        def __init__(self, payload):
            self._payload = payload

        def read(self, *_a):
            return json.dumps(self._payload).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    # every page answers with a record and a next cursor, so the walk never exhausts the
    # cursor and stops only at the page cap, which means more subdomains remain unfetched
    _next = "https://www.virustotal.com/api/v3/domains/example.com/subdomains?cursor=more"

    def capped(request, timeout=0):
        return _Resp({"data": [{"id": "api.example.com"}], "links": {"next": _next}})

    monkeypatch.setattr(urllib.request, "urlopen", capped)
    result = domains.virustotal_subdomains("example.com")
    assert result.truncated is True
    assert "api.example.com" in result

    # a walk that exhausts the cursor before the cap is complete, not truncated
    def exhausts(request, timeout=0):
        return _Resp({"data": [{"id": "api.example.com"}], "links": {}})

    monkeypatch.setattr(urllib.request, "urlopen", exhausts)
    assert domains.virustotal_subdomains("example.com").truncated is False

def test_otx_passive_dns_parses_and_flags_the_cap(monkeypatch):
    import urllib.request

    from opfor.scenarios.attacksurface import config
    from opfor.scenarios.attacksurface.assets.domain import sources as domains

    # the parse keeps hosts under the domain and drops the apex and any other domain, apart
    # from the network so it is driven by a fixture
    reply = {"passive_dns": [
        {"hostname": "api.example.com"},
        {"hostname": "dev.example.com."},
        {"hostname": "example.com"},
        {"hostname": "other.test"},
    ]}
    assert domains.subdomains_from_otx(reply, "example.com") == {"api.example.com", "dev.example.com"}

    # no key leaves the source out of the union, an empty enumeration rather than a call
    monkeypatch.setattr(config, "otx_key", lambda: "")
    assert domains.otx_subdomains("example.com") == set()

    monkeypatch.setattr(config, "otx_key", lambda: "otx")

    class _Resp:
        def __init__(self, payload):
            self._payload = payload

        def read(self, *_a):
            return json.dumps(self._payload).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    # a reply at the endpoint cap means more hosts exist unfetched, so it is flagged truncated
    capped = {"passive_dns": [{"hostname": f"h{i}.example.com"} for i in range(500)], "count": 500}
    monkeypatch.setattr(urllib.request, "urlopen", lambda request, timeout=0: _Resp(capped))
    result = domains.otx_subdomains("example.com")
    assert result.truncated is True
    assert len(result) == 500

def test_dnsdumpster_parses_and_flags_the_free_tier_cap(monkeypatch):
    import urllib.request

    from opfor.scenarios.attacksurface import config
    from opfor.scenarios.attacksurface.assets.domain import sources as domains

    # the parse keeps hosts under the domain from the a and cname records, and the domain
    # suffix drops the mail and nameserver records that point off the domain
    reply = {
        "a": [{"host": "api.example.com"}, {"host": "www.example.com"}],
        "cname": [{"host": "cdn.example.com"}],
        "mx": [{"host": "10 aspmx.l.google.com"}],
        "ns": [{"host": "ns-1.awsdns-31.co.uk"}],
        "total_a_recs": "2",
    }
    assert domains.subdomains_from_dnsdumpster(reply, "example.com") == {
        "api.example.com", "www.example.com", "cdn.example.com"}

    # no key leaves the source out of the union, an empty enumeration rather than a call
    monkeypatch.setattr(config, "dnsdumpster_key", lambda: "")
    assert domains.dnsdumpster_subdomains("example.com") == set()

    monkeypatch.setattr(config, "dnsdumpster_key", lambda: "dd")

    class _Resp:
        def __init__(self, payload):
            self._payload = payload

        def read(self, *_a):
            return json.dumps(self._payload).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    # the free tier returns fewer a records than the total it reports, so more remain and
    # the reply is flagged truncated rather than passed off as complete
    capped = {"a": [{"host": f"h{i}.example.com"} for i in range(50)], "total_a_recs": "205"}
    monkeypatch.setattr(urllib.request, "urlopen", lambda request, timeout=0: _Resp(capped))
    result = domains.dnsdumpster_subdomains("example.com")
    assert result.truncated is True
    assert len(result) == 50

def test_certspotter_token_429_falls_back_to_an_anonymous_walk(monkeypatch):
    import urllib.error
    import urllib.request

    from opfor.scenarios.attacksurface import config
    from opfor.scenarios.attacksurface.assets.domain import sources as domains

    monkeypatch.setattr(config, "certspotter_token", lambda: "spent-token")

    class _Resp:
        def __init__(self, payload):
            self._payload = payload

        def read(self, *_a):
            return json.dumps(self._payload).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    # the token walk answers 429 as if its account quota were spent, the anonymous walk
    # answers with records, so the source recovers rather than going blind
    def fake_urlopen(request, timeout=0):
        if request.get_header("Authorization"):
            raise urllib.error.HTTPError(request.full_url, 429, "Too Many Requests", {}, None)
        return _Resp([{"dns_names": ["api.example.com", "www.example.com"]}])

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    assert domains.certspotter_subdomains("example.com") == {"api.example.com", "www.example.com"}

def test_certspotter_token_error_that_is_not_429_is_raised(monkeypatch):
    import urllib.error
    import urllib.request

    from opfor.scenarios.attacksurface import config
    from opfor.scenarios.attacksurface.assets.domain import sources as domains

    monkeypatch.setattr(config, "certspotter_token", lambda: "tok")

    # a non-429 stays loud, it is not a quota signal and must not be swallowed as empty
    def fake_urlopen(request, timeout=0):
        raise urllib.error.HTTPError(request.full_url, 500, "Server Error", {}, None)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(urllib.error.HTTPError):
        domains.certspotter_subdomains("example.com")

def test_pivot_failure_still_closes_and_is_loud():
    def boom(domain):
        raise TimeoutError("certspotter slow")

    scenario = _make(pivot_fn=boom)
    world = _seed()
    report = run(scenario, world, scope=Scope(max_tier="recon", hosts=(ROOT,)), budget=Budget(500))
    assert report.closed
    assert any("failed" in n and "domain_pivot" in n for n in report.notes)

def test_registrant_pivot_is_off_without_a_key():
    # the default seam stays off when no key is set, so the run has no registrant fact
    world = _seed()
    _run(world)
    assert not world.has_fact("org:ExampleCorp", "registrant")

def test_registrant_pivot_discovers_a_root_when_wired():
    world = _seed()
    run(_with_reverse(), world, scope=Scope(max_tier="recon", hosts=(ROOT,)), budget=Budget(500))
    org = world.node("domain:example.org")
    assert org is not None
    assert org.payload.source == "reverse-whois"
    assert org.payload.confidence == "confirmed"
    assert "registration record names ExampleCorp" in org.payload.evidence

def test_registrant_root_is_an_info_finding():
    world = _seed()
    report = run(_with_reverse(), world, scope=Scope(max_tier="recon", hosts=(ROOT,)), budget=Budget(500))
    roots = {f.where: f for f in report.findings if f.data.get("kind") == "root"}
    assert "example.org" in roots
    assert roots["example.org"].data["source"] == "reverse-whois"

def test_registrant_pivot_failure_still_closes_and_is_loud():
    def boom(term, api_key=""):
        raise TimeoutError("provider slow")

    world = _seed()
    report = run(_with_reverse(boom), world, scope=Scope(max_tier="recon", hosts=(ROOT,)), budget=Budget(500))
    assert report.closed
    assert any("failed" in n and "domain_registrant" in n for n in report.notes)

def test_roots_from_reverse_whois_reads_both_shapes():
    from opfor.scenarios.attacksurface.assets.domain.sources import roots_from_reverse_whois

    as_strings = {"domainsList": ["a.example.org", "b.example.net"]}
    assert roots_from_reverse_whois(as_strings, "Acme") == {
        "example.org": "registration record names Acme",
        "example.net": "registration record names Acme",
    }
    as_records = {"domainsList": [{"domainName": "c.example.io"}]}
    assert roots_from_reverse_whois(as_records, "Acme") == {
        "example.io": "registration record names Acme"
    }

def test_subdomains_from_vt_reads_relationship_ids():
    from opfor.scenarios.attacksurface.assets.domain.sources import subdomains_from_vt

    page = {"data": [{"id": "api.example.com"}, {"id": "*.mail.example.com"},
                     {"id": "unrelated.test"}]}
    # a wildcard keeps its star, so the enumeration can flag it rather than lose it
    assert subdomains_from_vt(page, "example.com") == {"api.example.com", "*.mail.example.com"}

def test_virustotal_is_skipped_without_a_key(monkeypatch):
    from opfor.scenarios.attacksurface.assets.domain import sources as d

    monkeypatch.delenv("OPFOR_VIRUSTOTAL_API_KEY", raising=False)
    # no key means the source contributes nothing and makes no network call
    assert d.virustotal_subdomains("example.com") == set()

def test_certspotter_flags_truncation_when_the_page_budget_is_spent(monkeypatch):
    """A walk that spends its whole page budget on full pages leaves later certificates
    unread, so it reports the blind spot rather than passing as complete, invariant 5."""
    import urllib.request

    from opfor.scenarios.attacksurface import config
    from opfor.scenarios.attacksurface.assets.domain import sources as domains

    monkeypatch.setattr(config, "certspotter_token", lambda: "")

    class _Resp:
        def __init__(self, payload):
            self._payload = payload

        def read(self, *_a):
            return json.dumps(self._payload).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    # every page is full and carries an id cursor, so the bounded walk never runs dry
    def fake_urlopen(request, timeout=0):
        return _Resp([{"id": "999", "dns_names": ["api.example.com"]}])

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    result = domains.certspotter_subdomains("example.com")
    assert result == {"api.example.com"}
    assert result.truncated is True

def test_certspotter_does_not_flag_truncation_when_the_cursor_runs_dry(monkeypatch):
    import urllib.request

    from opfor.scenarios.attacksurface import config
    from opfor.scenarios.attacksurface.assets.domain import sources as domains

    monkeypatch.setattr(config, "certspotter_token", lambda: "")

    class _Resp:
        def __init__(self, payload):
            self._payload = payload

        def read(self, *_a):
            return json.dumps(self._payload).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    # a page with no id cursor ends the walk, so the enumeration is complete
    def fake_urlopen(request, timeout=0):
        return _Resp([{"dns_names": ["api.example.com"]}])

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    result = domains.certspotter_subdomains("example.com")
    assert result.truncated is False

def test_certspotter_non_list_response_fails_loud(monkeypatch):
    import urllib.request

    from opfor.scenarios.attacksurface.assets.domain.sources import passive

    class _Resp:
        def read(self, *_a):
            return json.dumps({"message": "rate limited"}).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: _Resp())
    # a certspotter error object is a dict, not a list, and must fail loud rather than crash
    # on issuances[-1] or extend records with dict keys
    with pytest.raises(RuntimeError):
        passive._certspotter_issuances("example.com", token=None, pages=1)

def test_permutation_candidates_cross_pollinate_observed_labels_only():
    from opfor.scenarios.attacksurface.assets.domain.capabilities.discovery import (
        permutation_candidates)

    observed = ["api.example.com", "dev.eu.example.com"]
    candidates = permutation_candidates("example.com", observed)
    # every observed leftmost label is tried at every observed structure, drawing only on what
    # was seen, so the label dev lands at the api structure and api at the eu structure
    assert "dev.example.com" in candidates
    assert "api.eu.example.com" in candidates
    # an observed name is never re-emitted, and no label comes from outside the observed set
    assert "api.example.com" not in candidates
    assert not any(c.startswith(("www.", "staging.", "admin.")) for c in candidates)

def test_permute_subdomains_confirms_only_resolving_candidates_and_skips_a_wildcard_zone():
    from opfor.core import Done, Node, Task, World
    from opfor.scenarios.attacksurface.assets.domain.capabilities.discovery import (
        PermuteSubdomains)
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData

    def seed():
        world = World()
        world.add(Node(id="domain:example.com", type="domain",
                       payload=DomainData(name="example.com", root="example.com", source="hint")))
        for name in ("api.example.com", "dev.eu.example.com"):
            world.add(Node(id=f"domain:{name}", type="domain",
                           payload=DomainData(name=name, root="example.com", source="passive")))
        return world

    resolving = {"dev.example.com"}

    def resolve(name):
        answers = name in resolving
        return {"resolvable": answers, "addresses": ("1.2.3.4",) if answers else (), "cnames": ()}

    out = PermuteSubdomains(resolve).run(
        Task(capability="domain_permute", node="domain:example.com"), seed())
    assert isinstance(out, Done)
    minted = {n.id for f in out.facts for n in f.yields}
    # a candidate that resolves under a no-wildcard root is confirmed and minted, one that does
    # not resolve is not, so a name is never invented without evidence
    assert "domain:dev.example.com" in minted
    assert "domain:api.eu.example.com" not in minted

    def wildcard(name):
        return {"resolvable": True, "addresses": ("9.9.9.9",), "cnames": ()}

    out2 = PermuteSubdomains(wildcard).run(
        Task(capability="domain_permute", node="domain:example.com"), seed())
    # a wildcard zone answers every name, so nothing is confirmed, only the bare fact is recorded
    assert isinstance(out2, Done)
    assert not any(f.yields for f in out2.facts)
    assert any(f.kind == "permuted" for f in out2.facts)

def test_path_permutations_derive_parents_and_version_twins_from_observed_only():
    from opfor.scenarios.attacksurface.assets.domain.sources.parsers import path_permutations

    got = path_permutations(["/api/v1/users", "/static/app.js"])
    # parent directories of an observed path, where a listing above a known file would show
    assert {"/api/", "/api/v1/", "/static/"} <= set(got)
    # version-bumped twins of a vN segment, where an older or newer version often sits less guarded
    assert "/api/v2/users" in got and "/api/v0/users" in got
    # an observed path is never re-emitted, and nothing comes from outside the observed segments
    assert "/api/v1/users" not in got and "/static/app.js" not in got
    assert not any("admin" in p or "backup" in p for p in got)

def test_permute_paths_capability_emits_derived_candidates_from_observed():
    from opfor.core import Done, Fact, Node, Task, World
    from opfor.scenarios.attacksurface.assets.domain.capabilities.http import PermutePaths
    from opfor.scenarios.attacksurface.assets.domain.types import Candidates, DomainData

    world = World()
    world.add(Node(id="domain:h.example.com", type="domain",
                   payload=DomainData(name="h.example.com", root="example.com", source="hint")))
    world.absorb((Fact(kind="candidates", about="domain:h.example.com",
                       payload=Candidates(source="harvest", paths=("/api/v1/users",))),))
    out = PermutePaths().run(
        Task(capability="domain_permute_paths", node="domain:h.example.com"), world)
    assert isinstance(out, Done)
    # the run-once marker plus a candidates fact the interface probe will confirm
    assert any(f.kind == "path_permuted" for f in out.facts)
    derived = [p for f in out.facts if f.kind == "candidates" for p in f.payload.paths]
    assert "/api/" in derived and "/api/v2/users" in derived

def test_permute_rule_waits_for_passive_enumeration_then_runs_once():
    from opfor.core import Fact, Node, World
    from opfor.scenarios.attacksurface.assets.domain.planner import _permute_rule
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData

    world = World()
    world.add(Node(id="domain:example.com", type="domain",
                   payload=DomainData(name="example.com", root="example.com", source="hint")))
    # before passive enumeration named the labels, there is nothing principled to permute
    assert _permute_rule(world) == []
    world.absorb((Fact(kind="enumerated", about="domain:example.com"),))
    assert [t.capability for t in _permute_rule(world)] == ["domain_permute"]
    # once it has run, its fact keeps it from firing again
    world.absorb((Fact(kind="permuted", about="domain:example.com"),))
    assert _permute_rule(world) == []

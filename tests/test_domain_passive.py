from __future__ import annotations

import json

import pytest


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

def test_subdomains_drops_dns_control_record_names(monkeypatch):
    # passive DNS returns control records (_dmarc, _domainkey, _acme-challenge); these are not
    # hosts and must not be admitted as probeable subdomains, a validation label unwraps to its host
    from opfor.scenarios.attacksurface.assets.domain.sources import passive as domains

    monkeypatch.setattr(domains, "certspotter_subdomains",
                        lambda d: {"api.example.com", "_dmarc.example.com",
                                   "_domainkey.example.com", "_acme-challenge.www.example.com"})
    monkeypatch.setattr(domains, "wayback_subdomains", lambda d: domains.Enumeration())
    result = set(domains.subdomains("example.com"))
    assert "api.example.com" in result
    assert "_dmarc.example.com" not in result
    assert "_domainkey.example.com" not in result
    assert "www.example.com" in result  # the acme-challenge validation label unwraps to its host


def test_subdomains_union_merges_the_keyless_windows(monkeypatch):
    # certificate logs and the archive have different windows, so the union is their merge
    from opfor.scenarios.attacksurface.assets.domain.sources import passive as domains

    monkeypatch.setattr(domains, "certspotter_subdomains", lambda d: {"cert-only.example.com"})
    monkeypatch.setattr(domains, "wayback_subdomains", lambda d: domains.Enumeration({"archived.example.com"}))
    result = set(domains.subdomains("example.com"))
    assert {"cert-only.example.com", "archived.example.com"} <= result


def test_wayback_subdomains_extracts_hosts_under_the_domain(monkeypatch):
    import urllib.request
    from opfor.scenarios.attacksurface.assets.domain.sources import passive as domains

    rows = [["original"],
            ["https://api.example.com/v1"],
            ["http://blog.example.com/post?a=1"],
            ["https://example.com/"],            # the apex root, not a subdomain
            ["https://cdn.other.com/x"]]         # a foreign host linked from an archived page

    class _Resp:
        def read(self, *_a):
            return json.dumps(rows).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: _Resp())
    out = domains.wayback_subdomains("example.com")
    assert "api.example.com" in out and "blog.example.com" in out
    assert "example.com" not in out          # apex is not a subdomain
    assert "cdn.other.com" not in out        # foreign host is dropped


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


def test_permute_subdomains_catches_a_wildcard_on_a_deeper_zone_not_only_the_apex():
    # regression: an apex-only wildcard baseline missed *.eu.example.com, so every
    # label.eu.example.com resolved to the catch-all and was minted as a confirmed host
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

    def resolve(name):
        # a wildcard on the deeper zone eu.example.com answers every name there, while the apex
        # zone example.com has no wildcard; dev.example.com is a real host under the apex
        answers = name.endswith(".eu.example.com") or name == "dev.example.com"
        return {"resolvable": answers, "addresses": ("9.9.9.9",) if answers else (), "cnames": ()}

    out = PermuteSubdomains(resolve).run(
        Task(capability="domain_permute", node="domain:example.com"), seed())
    assert isinstance(out, Done)
    minted = {n.id for f in out.facts for n in f.yields}
    # the real apex host is confirmed, the deep-wildcard candidate is not invented off the catch-all
    assert "domain:dev.example.com" in minted
    assert "domain:api.eu.example.com" not in minted
    # the wildcard zone is surfaced as a coverage gap rather than silently swallowed
    assert any(f.kind == "coverage_gap" for f in out.facts)

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

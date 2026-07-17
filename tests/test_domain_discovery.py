from __future__ import annotations

import json

import pytest

from opfor.core import Budget, MockProvider, Node, Phase, Scope, World, run
from opfor.core.result import CLOSED
from opfor.scenarios.attacksurface import build
from opfor.scenarios.attacksurface.triage import TriageError, _finding_from_dict
from opfor.scenarios.attacksurface.types import Org

from tests.surface_fixtures import *


def test_run_closes():
    report = _run(_seed())
    assert report.closed
    assert report.status == CLOSED
    assert report.reached == Phase.TRIAGE


def test_expands_both_asset_classes_from_the_org():
    world = _seed()
    _run(world)
    assert {n.payload.name for n in world.nodes("domain")} >= {"www.example.com", "admin.example.com"}
    assert {n.payload.login for n in world.nodes("github_org")} == {"examplecorp"}
    assert len(world.nodes("github_repo")) == 2


def test_wildcard_certificate_is_reported_as_a_blind_spot():
    # *.dev.example.com hides its hosts from CT, the run must say so rather than look clean
    report = _run(_seed())
    blind = [f for f in report.findings if f.data.get("kind") == "blindspot"]
    assert len(blind) == 1
    assert blind[0].severity == "INFO"
    assert "dev.example.com" in blind[0].data["bases"]


def test_truncated_enumeration_is_reported_as_a_blind_spot():
    # a passive source that stopped at its page cap left subdomains unfetched, the run must
    # say so rather than present the bounded set as the complete surface
    from opfor.scenarios.attacksurface.assets.domain.sources import Enumeration

    def enum_truncated(root):
        found = Enumeration({"api.example.com"})
        found.truncated = True
        return found

    report, _scenario, _world = _run_capturing(enumerate_fn=enum_truncated)
    trunc = [f for f in report.findings if f.id == "finding:blindspot:enumeration"]
    assert len(trunc) == 1
    assert trunc[0].severity == "INFO"
    assert "example.com" in trunc[0].data["roots"]


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


def test_inventory_hosts_enter_the_surface_as_enriched_leaves():
    # a DNS-export host is resolved and triaged, but not re-enumerated, since it is a leaf
    world = _seed(hosts=("api.dev.example.com",))
    _run(world)
    node = world.node("domain:api.dev.example.com")
    assert node.payload.source == "inventory"
    assert node.payload.root == "example.com"
    assert world.has_fact(node.id, "resolved")
    assert not world.has_fact(node.id, "enumerated")


def test_wildcard_base_node_is_flagged():
    from opfor.core import Node, World
    from opfor.scenarios.attacksurface.assets.domain.capabilities import Subdomains
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData
    from opfor.scenarios.attacksurface.types import Org

    world = World()
    world.add(Node(id="org:x", type="org", payload=Org(name="X", domains=("example.com",))))
    world.add(Node(id="domain:example.com", type="domain",
                   payload=DomainData(name="example.com", root="example.com", source="hint")))
    cap = Subdomains(lambda root: {"*.dev.example.com", "api.example.com"})
    from opfor.core import Task
    outcome = cap.run(Task(capability="domain_subdomains", node="domain:example.com"), world)
    nodes = {n.payload.name: n.payload for n in outcome.facts[0].yields}
    assert nodes["dev.example.com"].wildcard is True
    assert nodes["api.example.com"].wildcard is False


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


def test_http_probe_tries_every_public_ip_retries_timeouts_and_raises_the_unexpected(monkeypatch):
    from opfor.scenarios.attacksurface.assets.domain import http as domains

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


def test_signal_headers_keeps_identity_drops_noise_and_masks_cookie_value():
    from opfor.scenarios.attacksurface.assets.domain import http as domains

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


def test_github_org_is_info_inventory():
    report = _run(_seed())
    gh = [f for f in report.findings if f.data["kind"] == "github_org"]
    assert gh and gh[0].where == "examplecorp"
    assert gh[0].severity == "INFO"
    assert gh[0].data["repos"] == 2


def test_github_attribution_keeps_the_owned_drops_the_namesake_flags_the_unproven():
    # three candidates match the name: one links to the in-scope root, one links to a
    # different root and is a namesake, one has no link and cannot be proven either way
    def search(name, token=""):
        return [
            {"login": "examplecorp", "url": "u", "org_id": 1, "name": "Example Corp",
             "blog": "https://example.com", "email": "", "verified": False},
            {"login": "example-lasers", "url": "u", "org_id": 2, "name": "Example Lasers",
             "blog": "https://example-lasers.io", "email": "", "verified": False},
            {"login": "examplish", "url": "u", "org_id": 3, "name": "Examplish",
             "blog": "", "email": "", "verified": False},
        ]

    report, _, world = _run_capturing(_seed(), search_fn=search)
    logins = {n.payload.login for n in world.nodes("github_org")}
    # the namesake proven to belong elsewhere is dropped, the other two are kept
    assert logins == {"examplecorp", "examplish"}
    attributed = {n.payload.login for n in world.nodes("github_org") if n.payload.attributed}
    assert attributed == {"examplecorp"}
    # the owned org is its own finding, the unproven one is collapsed into a caveat
    kinds = {f.data.get("kind") for f in report.findings}
    assert "github_org" in kinds and "github_unattributed" in kinds
    caveat = next(f for f in report.findings if f.data.get("kind") == "github_unattributed")
    assert caveat.data["logins"] == ["examplish"]


def test_class_restriction_runs_only_that_class():
    # github only: no domain nodes discovered, no domain findings
    world = _seed(classes=("github",))
    report = _run(world)
    assert report.closed
    assert world.nodes("domain") == ()
    assert world.nodes("github_org")
    assert all(f.data["kind"] == "github_org" for f in report.findings)


def test_http_probe_denied_when_domain_out_of_scope():
    world = _seed()
    report = _run(world, scope=Scope(max_tier="recon", hosts=("other.test",)))
    assert report.closed
    assert not world.has_fact("domain:example.com", "http")
    assert any("denied" in n and "domain_http" in n for n in report.notes)


def test_total_resolution_failure_reports_incomplete_not_dangling():
    # when not one name resolves, the resolver is the problem, so the run must say
    # incomplete rather than call every name dangling
    def none_resolve(name):
        return {"resolvable": False, "addresses": ()}

    scenario = _make(resolve_fn=none_resolve)
    world = _seed(classes=("domain",))
    report = run(scenario, world, scope=Scope(max_tier="recon", hosts=(ROOT,)), budget=Budget(500))
    kinds = {f.data.get("kind") for f in report.findings}
    assert "incomplete" in kinds
    assert "dangling" not in kinds


def test_github_search_failure_still_closes():
    def boom(name, token=""):
        raise TimeoutError("github slow")

    scenario = _make(search_fn=boom)
    world = _seed()
    report = run(scenario, world, scope=Scope(max_tier="recon", hosts=(ROOT,)), budget=Budget(500))
    assert report.closed
    # the failure is loud in the report, not only in the ledger
    assert any("failed" in n and "discover_github" in n for n in report.notes)


def test_no_hint_domains_still_closes_via_github():
    # a bare name with no hint domains and the domain class off still closes on github
    world = _seed(domains=(), classes=("github",))
    report = _run(world)
    assert report.closed
    assert world.nodes("domain") == ()
    assert world.nodes("github_org")


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


def test_registrable_root_keeps_multi_label_suffixes():
    from opfor.scenarios.attacksurface.hostnames import registrable_root

    assert registrable_root("api.example.com") == "example.com"
    assert registrable_root("example.com") == "example.com"
    assert registrable_root("a.b.example.co.uk") == "example.co.uk"


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


def test_fetch_url_tries_every_public_address_not_only_the_first(monkeypatch):
    # a host whose first address is dead but second is live must still be enriched, so the
    # fetch seam iterates all public addresses the way the alive probe does
    from opfor.scenarios.attacksurface.assets.domain import http as domains
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
    from opfor.scenarios.attacksurface.assets.domain import http as domains

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
    from opfor.scenarios.attacksurface.assets.domain import http as domains

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


def test_signal_headers_capture_security_headers_complete_past_the_identification_cap():
    from opfor.scenarios.attacksurface.assets.domain import http as domains

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
        PermuteSubdomains, _WILDCARD_PROBE)
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
    from opfor.scenarios.attacksurface.assets.domain.parsers import path_permutations

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


def test_port_scan_reports_open_service_ports_with_banners(monkeypatch):
    from opfor.scenarios.attacksurface.assets.domain import http as domains

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
    from opfor.scenarios.attacksurface.assets.domain import http as domains

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
    task = Task(capability="port_scan", node="domain:h.example.com", scope_host="h.example.com")

    ok = PortServices(lambda n, a: {"reachable": True, "scanned": 24,
                                    "open": [{"port": 6379, "service": "redis", "banner": ""}]})
    out = ok.run(task, world)
    assert isinstance(out, Done)
    assert out.facts[0].payload.open_ports[0].port == 6379

    def boom(name, addresses):
        raise RuntimeError("scan down")

    assert isinstance(PortServices(boom).run(task, world), Failed)


def test_tls_probe_reports_a_valid_certificate_with_its_expiry(monkeypatch):
    from opfor.scenarios.attacksurface.assets.domain import http as domains

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
    from opfor.scenarios.attacksurface.assets.domain import http as domains

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
    from opfor.scenarios.attacksurface.assets.domain import http as domains

    assert domains.tls_probe("h.example.com", ("10.0.0.1",))["reason"] == "no-public-address"

    def refuse(name, ip, context):
        raise OSError("connection refused")

    monkeypatch.setattr(domains, "_tls_connect", refuse)
    out = domains.tls_probe("h.example.com", ("1.2.3.4",))
    assert out["reachable"] is False


def test_tls_capability_reports_posture_and_fails_loud_on_error():
    from opfor.core import Done, Failed, Node, Task, World
    from opfor.scenarios.attacksurface.assets.domain.capabilities.tls import TlsSecurity
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData

    world = World()
    world.add(Node(id="domain:h.example.com", type="domain",
                   payload=DomainData(name="h.example.com", root="example.com", source="hint")))
    task = Task(capability="tls", node="domain:h.example.com", scope_host="h.example.com")

    ok = TlsSecurity(lambda n, a: {"reachable": True, "valid": False,
                                   "validity_error": "certificate has expired"})
    out = ok.run(task, world)
    assert isinstance(out, Done)
    assert out.facts[0].payload.valid is False
    assert "expired" in out.facts[0].payload.validity_error

    def boom(name, addresses):
        raise RuntimeError("tls down")

    assert isinstance(TlsSecurity(boom).run(task, world), Failed)


def test_signal_headers_keep_cookie_flags_but_drop_the_secret_value():
    from opfor.scenarios.attacksurface.assets.domain import http as domains

    class Resp:
        def getheaders(self):
            return [("Set-Cookie", "sid=SECRETVALUE; Path=/; Secure; HttpOnly; SameSite=Lax"),
                    ("Set-Cookie", "tracker=xyztoken")]

    cookies = [v for n, v in domains._signal_headers(Resp()) if n == "set-cookie"]
    # the flags survive so triage can judge them, but the secret value never enters the report
    assert "sid; Path=/; Secure; HttpOnly; SameSite=Lax" in cookies
    assert "tracker" in cookies
    assert all("SECRETVALUE" not in v and "xyztoken" not in v for v in cookies)


def test_dns_email_posture_reads_spf_dmarc_caa_and_dnssec(monkeypatch):
    from opfor.scenarios.attacksurface.assets.domain import http as domains

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


def test_doh_lookup_fails_over_resolvers_and_raises_when_all_error(monkeypatch):
    from opfor.scenarios.attacksurface.assets.domain import http as domains

    tried = []

    def records(resolver, name, rtype):
        tried.append(resolver)
        return (2, [], False)  # SERVFAIL on every resolver, a resolver error not a real answer

    monkeypatch.setattr(domains, "_doh_records", records)
    with pytest.raises(RuntimeError):
        domains._doh_lookup("example.com", "TXT")
    # every resolver was tried before the failure was raised, so one flaky resolver does not blind it
    assert len(tried) == len(domains._DOH_RESOLVERS)


def test_dns_email_capability_reports_records_and_fails_loud_on_error():
    from opfor.core import Done, Failed, Node, Task, World
    from opfor.scenarios.attacksurface.assets.domain.capabilities.dns import DnsEmailSecurity
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData

    world = World()
    world.add(Node(id="domain:example.com", type="domain",
                   payload=DomainData(name="example.com", root="example.com", source="hint")))
    task = Task(capability="dns_email", node="domain:example.com")

    ok = DnsEmailSecurity(lambda d: {"spf": ("v=spf1 -all",), "dmarc": "", "caa": (), "dnssec": True})
    out = ok.run(task, world)
    assert isinstance(out, Done)
    assert out.facts[0].payload.spf == ("v=spf1 -all",)
    assert out.facts[0].payload.dnssec is True

    def boom(domain):
        raise RuntimeError("dns down")

    # a lookup that fails is a loud Failed, never a silent clean absence of records
    assert isinstance(DnsEmailSecurity(boom).run(task, world), Failed)


def test_graphql_introspection_raises_on_a_server_error(monkeypatch):
    from opfor.scenarios.attacksurface.assets.domain import http as domains
    monkeypatch.setattr(domains, "resolve_host", lambda n: {"addresses": ("2.2.2.2",)})
    monkeypatch.setattr(domains, "_connect", lambda *a, **k: (500, "", "", "", "", ()))
    # a 5xx introspection is errored and unknown, never reported as safely disabled
    with pytest.raises(RuntimeError):
        domains.graphql_introspect("h.example.com", "/graphql")


def test_graphql_introspection_is_off_on_a_client_refusal(monkeypatch):
    from opfor.scenarios.attacksurface.assets.domain import http as domains
    monkeypatch.setattr(domains, "resolve_host", lambda n: {"addresses": ("2.2.2.2",)})
    monkeypatch.setattr(domains, "_connect",
                        lambda *a, **k: (403, "", "", "introspection disabled", "", ()))
    # a 4xx is an intentional refusal, a genuine off, so None rather than a raise
    assert domains.graphql_introspect("h.example.com", "/graphql") is None


def test_subdomain_enumeration_partial_failure_surfaces_a_coverage_gap():
    from opfor.core import Done, Task
    from opfor.scenarios.attacksurface.assets.domain.capabilities.discovery import Subdomains
    from opfor.scenarios.attacksurface.assets.domain.passive import Enumeration
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData

    world = World()
    world.add(Node(id="domain:example.com", type="domain",
                   payload=DomainData(name="example.com", root="example.com", source="seed")))

    def enumerate_fn(root):
        found = Enumeration({"a.example.com"})
        found.source_errors = ("virustotal: down",)
        found.source_count = 3
        return found

    outcome = Subdomains(enumerate_fn).run(
        Task(capability="domain_subdomains", node="domain:example.com"), world)
    assert isinstance(outcome, Done)
    # a source that failed while others answered is surfaced as a coverage gap, so the
    # partial subdomain set does not read as the full surface
    gaps = [f.payload for f in outcome.facts
            if f.kind == "coverage_gap" and f.payload.scan == "domain_subdomains"]
    assert gaps and gaps[0].failed == 1 and any("virustotal" in r for r in gaps[0].reasons)


def test_registrable_root_recognizes_country_second_levels_generally():
    from opfor.scenarios.attacksurface.hostnames import registrable_root
    # an uncurated country suffix is no longer mis-rooted, com.ph and co.nz keep three labels
    assert registrable_root("api.company.com.ph") == "company.com.ph"
    assert registrable_root("www.shop.co.nz") == "shop.co.nz"
    # the curated and default cases are unchanged
    assert registrable_root("host.example.co.uk") == "example.co.uk"
    assert registrable_root("a.b.example.com") == "example.com"
    assert registrable_root("api.example.com") == "example.com"


def test_resolve_host_treats_a_servfail_as_a_resolver_error_not_a_no_address(monkeypatch):
    import urllib.request

    from opfor.scenarios.attacksurface.assets.domain import http as domains

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


def test_registrable_root_leaves_an_ip_literal_unchanged():
    from opfor.scenarios.attacksurface.hostnames import registrable_root
    # an IP has no registrable root, folding it to the last two octets would mint a bogus root
    assert registrable_root("10.0.0.5") == "10.0.0.5"
    assert registrable_root("192.168.1.1") == "192.168.1.1"


def test_same_host_path_matches_a_mixed_case_host():
    from opfor.scenarios.attacksurface.assets.domain.parsers import same_host_path
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


def test_a_run_is_deterministic_across_repeats():
    # outcomes are absorbed in task-id order, not thread-completion order, so two identical
    # runs produce the same world and the same triage input
    a = _seed()
    _run(a)
    b = _seed()
    _run(b)
    assert [n.id for n in a.nodes()] == [n.id for n in b.nodes()]


def test_budget_cap_is_not_overshot_by_a_batch():
    from opfor.core import Budget, Scope, run
    world = _seed()
    budget = Budget(2)
    run(_make(), world, scope=Scope(max_tier="recon", hosts=(ROOT,)), budget=budget)
    # a batch is capped to the remaining budget, so the runaway ceiling is not blown past
    assert budget.steps <= 2


def test_connect_closes_the_raw_socket_when_the_tls_handshake_fails(monkeypatch):
    import socket
    import ssl

    from opfor.scenarios.attacksurface.assets.domain import http as domains

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


def test_readonly_fetch_refuses_a_host_that_resolves_only_to_a_private_address(monkeypatch):
    from opfor.scenarios.attacksurface.assets.domain import http as domains
    monkeypatch.setattr(domains, "resolve_host",
                        lambda h: {"addresses": ("127.0.0.1",), "resolvable": True, "cnames": ()})
    # a name repointed at loopback between observation and replay must not be fetched
    assert domains.fetch_readonly("http://internal.example.com/x")["status"] is None


def test_readonly_fetch_pins_a_public_address_and_verifies_the_certificate(monkeypatch):
    from opfor.scenarios.attacksurface.assets.domain import http as domains
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


def test_fetch_public_url_uses_the_no_redirect_opener(monkeypatch):
    from opfor.scenarios.attacksurface.assets.domain import http as domains

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


def test_certspotter_non_list_response_fails_loud(monkeypatch):
    import urllib.request

    from opfor.scenarios.attacksurface.assets.domain import passive

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


def test_read_capped_stops_at_the_wall_clock_deadline(monkeypatch):
    from opfor.scenarios.attacksurface.assets.domain import http as domains
    clock = {"t": 0.0}
    monkeypatch.setattr(domains.time, "monotonic", lambda: clock["t"])

    class _Drip:
        def read1(self, n):
            clock["t"] += 20.0   # each read advances past the 30s deadline within two reads
            return b"x"

    body = domains._read_capped(_Drip(), read_limit=1000)
    # a slow-drip response is cut off at the deadline instead of tying the worker for 1000 bytes
    assert 0 < len(body) < 1000

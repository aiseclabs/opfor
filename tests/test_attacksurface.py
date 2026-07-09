"""attack-surface: an org name expands into ranked assets, driven by fake seams.

Fixtures use the reserved example domain from RFC 2606, so no real target is named in
the code and nothing here touches a live endpoint.
"""

from __future__ import annotations

from opfor.core import Budget, Node, Phase, Scope, World, run
from opfor.core.result import CLOSED
from opfor.scenarios.attacksurface import build
from opfor.scenarios.attacksurface.types import Org

ROOT = "example.com"

# Certificate transparency result for the hint root.
CRT = {ROOT: {"www.example.com", "admin.example.com", "old.example.com", "cdn.example.com",
              "spa.example.com", "cf.example.com"}}

# DNS per name, a name absent here is unresolvable. old.example.com is dangling.
DNS = {
    "example.com": {"resolvable": True, "addresses": ("1.1.1.1",)},
    "www.example.com": {"resolvable": True, "addresses": ("1.1.1.2",)},
    "admin.example.com": {"resolvable": True, "addresses": ("1.1.1.3",)},
    "cdn.example.com": {"resolvable": True, "addresses": ("1.1.1.4",)},
    "spa.example.com": {"resolvable": True, "addresses": ("1.1.1.5",)},
    "cf.example.com": {"resolvable": True, "addresses": ("1.1.1.6",)},
}

# HTTP per name. cdn points at an unclaimed bucket, admin is a live admin surface, spa is
# a single-page app that answers 200 for every path.
HTTP = {
    "example.com": {"alive": True, "status": 200, "url": "https://example.com/", "server": "nginx",
                    "title": "home", "body": "welcome"},
    "www.example.com": {"alive": True, "status": 200, "url": "https://www.example.com/", "server": "nginx",
                        "title": "home", "body": "welcome"},
    "admin.example.com": {"alive": True, "status": 200, "url": "https://admin.example.com/", "server": "nginx",
                          "title": "admin login", "body": "sign in"},
    "cdn.example.com": {"alive": True, "status": 404, "url": "https://cdn.example.com/", "server": "AmazonS3",
                        "title": "", "body": "<html>nosuchbucket</html>"},
    "spa.example.com": {"alive": True, "status": 200, "url": "https://spa.example.com/", "server": "cf",
                        "title": "app", "body": "<html>spa app single page</html>"},
    "cf.example.com": {"alive": True, "status": 200, "url": "https://cf.example.com/", "server": "cf",
                       "title": "app", "body": "<html>cf</html>"},
}

# GitHub search and repos, keyed off the org name.
GH_ORGS = {"ExampleCorp": [{"login": "examplecorp", "url": "https://github.com/examplecorp", "org_id": 7}]}
GH_REPOS = {
    "examplecorp": [
        {"full_name": "examplecorp/web", "url": "u1", "language": "Go", "pushed_at": "2026-06-01", "archived": False},
        {"full_name": "examplecorp/infra", "url": "u2", "language": "HCL", "pushed_at": "2026-05-01", "archived": False},
    ]
}


def _search(name, token=""):
    return list(GH_ORGS.get(name, []))


def _repos(login, token=""):
    return list(GH_REPOS.get(login, []))


# Interface probes per absolute url. Anything absent answers 404 and is skipped.
ENDPOINTS = {
    "https://admin.example.com/.git/config": {"status": 200, "body": "[core]\n\trepositoryformatversion = 0"},
    "https://admin.example.com/.env": {"status": 200, "body": "db_password=secret\napi_key=abc"},
    "https://admin.example.com/metrics": {"status": 401, "body": "unauthorized"},
    "https://admin.example.com/admin": {"status": 200, "body": "admin panel please sign in"},
    "https://example.com/robots.txt": {"status": 200, "body": "user-agent: *"},
}


def _fetch(name, addresses, path):
    url = f"https://{name}{path}"
    if name == "spa.example.com":
        # a single-page app: 200 HTML for every path, but a real JSON spec at one path
        if path == "/openapi.json":
            return {"status": 200, "url": url, "content_type": "application/json",
                    "server": "cf", "title": "", "body": '{"openapi":"3.0.0","paths":{}}'}
        return {"status": 200, "url": url, "content_type": "text/html",
                "server": "cf", "title": "", "body": "<html>spa app single page</html>"}
    if name == "cf.example.com":
        # a host that serves an empty 200 for /.env, the shape that used to false-positive
        if path == "/.env":
            return {"status": 200, "url": url, "content_type": "", "server": "cf", "title": "", "body": ""}
        return {"status": 404, "url": url, "content_type": "", "server": "", "title": "", "body": ""}
    d = ENDPOINTS.get(url, {"status": 404, "body": ""})
    return {"status": d["status"], "url": url, "content_type": d.get("ct", ""),
            "server": d.get("server", ""), "title": "", "body": d["body"].lower()}


# Certificate-SAN sibling roots per known root. example.com and example.net are bundled
# on one dedicated cert, evidence they share an owner. example.net pivots no further.
SIBLINGS = {ROOT: {"example.net": "shares a certificate with example.com, 2 roots on the cert"}}


def _pivot(domain):
    return dict(SIBLINGS.get(domain, {}))


# Reverse-WHOIS results keyed by search term. The org name resolves to a root registered
# to the same registrant, the definitional ownership signal.
WHOIS = {"ExampleCorp": {"example.org": "registration record names ExampleCorp"}}


def _reverse(term, api_key=""):
    return dict(WHOIS.get(term, {}))


# DNS brute-force hits per root, names that resolve but never appeared in CT. int.example.com
# stands for a wildcard-hidden or never-certed internal host.
BRUTE = {ROOT: {"int.example.com", "vpn.example.com"}}


def _brute(root, words):
    return set(BRUTE.get(root, set()))


def _enumerate(domain):
    return set(CRT.get(domain, set()))


def _resolve(name):
    return DNS.get(name, {"resolvable": False, "addresses": ()})


def _probe(name, addresses=()):
    return HTTP.get(name, {"alive": False, "status": None, "url": "", "server": "", "title": "", "body": ""})


def _scenario():
    return build(search_fn=_search, repos_fn=_repos, enumerate_fn=_enumerate, brute_fn=_brute,
                 pivot_fn=_pivot, resolve_fn=_resolve, probe_fn=_probe, fetch_fn=_fetch)


def _seed(*, domains=(ROOT,), classes=()):
    world = World()
    world.add(Node(id="org:ExampleCorp", type="org",
                   payload=Org(name="ExampleCorp", domains=tuple(domains), classes=tuple(classes))))
    return world


def _run(world, scope=None, budget=500):
    return run(_scenario(), world,
               scope=scope or Scope(max_tier="recon", hosts=(ROOT,)), budget=Budget(budget))


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


def test_domain_takeover_is_high():
    report = _run(_seed())
    takeover = [f for f in report.findings if f.data["kind"] == "takeover"]
    assert takeover and takeover[0].where == "cdn.example.com"
    assert takeover[0].severity == "HIGH"
    assert "Amazon S3" in takeover[0].title


def test_domain_dangling_is_low():
    report = _run(_seed())
    dangling = [f for f in report.findings if f.data["kind"] == "dangling"]
    assert [f.where for f in dangling] == ["old.example.com"]
    assert dangling[0].severity == "LOW"


def test_domain_interesting_is_medium():
    report = _run(_seed())
    exposed = [f for f in report.findings if f.data["kind"] == "exposed"]
    assert "admin.example.com" in {f.where for f in exposed}
    assert all(f.severity == "MEDIUM" for f in exposed)


def test_endpoints_enumerated_and_auth_classified():
    world = _seed()
    _run(world)
    eps = {n.id: n.payload for n in world.nodes("endpoint")}
    assert "endpoint:admin.example.com/.git/config" in eps
    assert eps["endpoint:admin.example.com/metrics"].auth_required is True
    assert eps["endpoint:admin.example.com/.env"].auth_required is False


def test_exposed_git_is_high_with_poc():
    report = _run(_seed())
    git = [f for f in report.findings if f.data.get("detector") == "exposed-git"]
    assert git and git[0].severity == "HIGH"
    assert "admin.example.com/.git/config" in git[0].data["poc"]


def test_exposed_env_is_high():
    report = _run(_seed())
    assert any(f.data.get("detector") == "exposed-env" and f.severity == "HIGH"
               for f in report.findings)


def test_authenticated_endpoint_is_not_an_unauth_finding():
    report = _run(_seed())
    assert not any(f.where.endswith("/metrics") for f in report.findings)


def test_unmatched_unauth_interface_is_info():
    report = _run(_seed())
    info = [f for f in report.findings
            if f.data.get("kind") == "unauth" and f.where.endswith("/admin")]
    assert info and info[0].severity == "INFO"


def test_expected_public_path_is_not_a_finding():
    report = _run(_seed())
    assert not any(f.where.endswith("/robots.txt") for f in report.findings)


def test_soft_200_host_is_not_flooded_with_unauth_findings():
    report = _run(_seed())
    spa = [f for f in report.findings
           if f.where.startswith("https://spa.example.com") and f.data.get("kind") == "unauth"]
    assert spa == []


def test_real_json_spec_on_soft_200_is_still_caught():
    report = _run(_seed())
    hits = [f for f in report.findings if f.where == "https://spa.example.com/openapi.json"]
    assert hits and hits[0].data.get("detector") == "openapi-spec"


def test_html_posing_as_swagger_is_not_flagged():
    report = _run(_seed())
    assert not any(f.where == "https://spa.example.com/swagger.json" for f in report.findings)


def test_empty_env_is_not_a_false_exposure():
    report = _run(_seed())
    env = [f for f in report.findings
           if f.where == "https://cf.example.com/.env" and f.data.get("kind") == "exposure"]
    assert env == []


def test_github_org_is_info_inventory():
    report = _run(_seed())
    gh = [f for f in report.findings if f.data["kind"] == "github_org"]
    assert gh and gh[0].where == "examplecorp"
    assert gh[0].severity == "INFO"
    assert gh[0].data["repos"] == 2


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

    scenario = build(search_fn=_search, repos_fn=_repos, enumerate_fn=_enumerate, brute_fn=_brute,
                     pivot_fn=_pivot, resolve_fn=none_resolve, probe_fn=_probe, fetch_fn=_fetch)
    world = _seed(classes=("domain",))
    report = run(scenario, world, scope=Scope(max_tier="recon", hosts=(ROOT,)), budget=Budget(500))
    kinds = {f.data.get("kind") for f in report.findings}
    assert "incomplete" in kinds
    assert "dangling" not in kinds


def test_github_search_failure_still_closes():
    def boom(name, token=""):
        raise TimeoutError("github slow")

    scenario = build(search_fn=boom, repos_fn=_repos, enumerate_fn=_enumerate, brute_fn=_brute,
                     pivot_fn=_pivot, resolve_fn=_resolve, probe_fn=_probe)
    world = _seed()
    report = run(scenario, world, scope=Scope(max_tier="recon", hosts=(ROOT,)), budget=Budget(500))
    assert report.closed
    # the domain class still runs and produces its findings
    assert any(f.data["kind"] == "takeover" for f in report.findings)
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
    assert net.payload.confidence == "confirmed"
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
    from opfor.scenarios.attacksurface.sources.domains import registrable_root

    assert registrable_root("api.example.com") == "example.com"
    assert registrable_root("example.com") == "example.com"
    assert registrable_root("a.b.example.co.uk") == "example.co.uk"


def test_shared_certificate_is_not_treated_as_ownership_evidence():
    from opfor.scenarios.attacksurface.sources.domains import sibling_roots_from_issuances

    # a dedicated cert bundling two roots yields the sibling
    dedicated = [{"dns_names": ["example.com", "www.example.net"]}]
    assert sibling_roots_from_issuances(dedicated, "example.com") == {
        "example.net": "shares a certificate with example.com, 2 roots on the cert"
    }
    # a multi-tenant cert bundling many unrelated roots proves nothing, so it is skipped
    shared = [{"dns_names": ["example.com", "a.org", "b.org", "c.org", "d.org", "e.org", "f.org"]}]
    assert sibling_roots_from_issuances(shared, "example.com") == {}


def test_pivot_failure_still_closes_and_is_loud():
    def boom(domain):
        raise TimeoutError("certspotter slow")

    scenario = build(search_fn=_search, repos_fn=_repos, enumerate_fn=_enumerate, brute_fn=_brute,
                     pivot_fn=boom, resolve_fn=_resolve, probe_fn=_probe, fetch_fn=_fetch)
    world = _seed()
    report = run(scenario, world, scope=Scope(max_tier="recon", hosts=(ROOT,)), budget=Budget(500))
    assert report.closed
    assert any("failed" in n and "domain_pivot" in n for n in report.notes)


def _with_reverse(reverse_fn=_reverse):
    return build(search_fn=_search, repos_fn=_repos, enumerate_fn=_enumerate, brute_fn=_brute,
                 pivot_fn=_pivot, reverse_whois_fn=reverse_fn, resolve_fn=_resolve,
                 probe_fn=_probe, fetch_fn=_fetch)


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
    from opfor.scenarios.attacksurface.sources.domains import roots_from_reverse_whois

    as_strings = {"domainsList": ["a.example.org", "b.example.net"]}
    assert roots_from_reverse_whois(as_strings, "Acme") == {
        "example.org": "registration record names Acme",
        "example.net": "registration record names Acme",
    }
    as_records = {"domainsList": [{"domainName": "c.example.io"}]}
    assert roots_from_reverse_whois(as_records, "Acme") == {
        "example.io": "registration record names Acme"
    }


def test_brute_force_finds_a_subdomain_ct_missed():
    world = _seed()
    _run(world)
    node = world.node("domain:int.example.com")
    assert node is not None
    assert node.payload.source == "brute"
    assert node.payload.root == ROOT
    assert node.payload.confidence == "confirmed"


def test_brute_force_runs_on_a_discovered_root_too():
    # the sibling root discovered by the cert pivot is also brute forced, so a name is
    # scheduled against it, proving brute force follows the snowball rather than the seed
    scenario = build(search_fn=_search, repos_fn=_repos, enumerate_fn=_enumerate,
                     brute_fn=_brute, pivot_fn=_pivot, resolve_fn=_resolve,
                     probe_fn=_probe, fetch_fn=_fetch)
    world = _seed()
    run(scenario, world, scope=Scope(max_tier="recon", hosts=(ROOT,)), budget=Budget(500))
    assert world.has_fact("domain:example.net", "bruteforced")


def test_brute_force_failure_still_closes_and_is_loud():
    def boom(root, words):
        raise TimeoutError("resolver slow")

    scenario = build(search_fn=_search, repos_fn=_repos, enumerate_fn=_enumerate,
                     brute_fn=boom, pivot_fn=_pivot, resolve_fn=_resolve,
                     probe_fn=_probe, fetch_fn=_fetch)
    world = _seed()
    report = run(scenario, world, scope=Scope(max_tier="recon", hosts=(ROOT,)), budget=Budget(500))
    assert report.closed
    assert any("failed" in n and "domain_bruteforce" in n for n in report.notes)


def test_subdomains_from_vt_reads_relationship_ids():
    from opfor.scenarios.attacksurface.sources.domains import subdomains_from_vt

    page = {"data": [{"id": "api.example.com"}, {"id": "*.mail.example.com"},
                     {"id": "unrelated.test"}]}
    assert subdomains_from_vt(page, "example.com") == {"api.example.com", "mail.example.com"}


def test_virustotal_is_skipped_without_a_key(monkeypatch):
    from opfor.scenarios.attacksurface.sources import domains as d

    monkeypatch.delenv("OPFOR_VIRUSTOTAL_KEY", raising=False)
    # no key means the source contributes nothing and makes no network call
    assert d.virustotal_subdomains("example.com") == set()


def test_brute_hits_drops_the_wildcard_catch_all():
    from opfor.scenarios.attacksurface.sources.domains import brute_hits

    # a.example.com is a real host on its own address, w.example.com only echoes the
    # wildcard address, and x.example.com does not resolve, so only a survives
    resolved = {
        "a.example.com": ["1.2.3.4"],
        "w.example.com": ["9.9.9.9"],
        "x.example.com": [],
    }
    assert brute_hits(resolved, {"9.9.9.9"}) == {"a.example.com"}

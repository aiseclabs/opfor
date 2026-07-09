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
CRT = {ROOT: {"www.example.com", "admin.example.com", "old.example.com", "cdn.example.com"}}

# DNS per name, a name absent here is unresolvable. old.example.com is dangling.
DNS = {
    "example.com": {"resolvable": True, "addresses": ("1.1.1.1",)},
    "www.example.com": {"resolvable": True, "addresses": ("1.1.1.2",)},
    "admin.example.com": {"resolvable": True, "addresses": ("1.1.1.3",)},
    "cdn.example.com": {"resolvable": True, "addresses": ("1.1.1.4",)},
}

# HTTP per name. cdn points at an unclaimed bucket, admin is a live admin surface.
HTTP = {
    "example.com": {"alive": True, "status": 200, "url": "https://example.com/", "server": "nginx",
                    "title": "home", "body": "welcome"},
    "www.example.com": {"alive": True, "status": 200, "url": "https://www.example.com/", "server": "nginx",
                        "title": "home", "body": "welcome"},
    "admin.example.com": {"alive": True, "status": 200, "url": "https://admin.example.com/", "server": "nginx",
                          "title": "admin login", "body": "sign in"},
    "cdn.example.com": {"alive": True, "status": 404, "url": "https://cdn.example.com/", "server": "AmazonS3",
                        "title": "", "body": "<html>nosuchbucket</html>"},
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


def _enumerate(domain):
    return set(CRT.get(domain, set()))


def _resolve(name):
    return DNS.get(name, {"resolvable": False, "addresses": ()})


def _probe(name):
    return HTTP.get(name, {"alive": False, "status": None, "url": "", "server": "", "title": "", "body": ""})


def _scenario():
    return build(search_fn=_search, repos_fn=_repos, enumerate_fn=_enumerate,
                 resolve_fn=_resolve, probe_fn=_probe)


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


def test_github_search_failure_still_closes():
    def boom(name, token=""):
        raise TimeoutError("github slow")

    scenario = build(search_fn=boom, repos_fn=_repos, enumerate_fn=_enumerate,
                     resolve_fn=_resolve, probe_fn=_probe)
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

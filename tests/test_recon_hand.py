from opfor.agent.brain import MockBrain
from opfor.engine.graph import SituationGraph
from opfor.engine.loop import AttackLoop
from opfor.engine.scope import Scope
from opfor.engine.state import Workspace
from opfor.model import Domain, Entrypoint, Target
from opfor.scenarios.recon.hand import ReconHand


def _seed(domain="example.com"):
    return Target(id=domain, kind="domain", props={"host": domain, "is_root": True})


def test_subdomains_merge_sources_and_keep_in_scope_only():
    # Two passive sources, one flaky, plus an unrelated name that must be dropped.
    def good(d):
        return ["api.example.com", "WWW.example.com", "*.api.example.com"]

    def flaky(d):
        raise OSError("source down")

    def other(d):
        return ["mail.example.com", "unrelated.org"]

    hand = ReconHand(subdomain_sources=[("good", good), ("flaky", flaky), ("other", other)])
    graph = SituationGraph()
    seed = _seed()
    graph.add_target(seed)

    ep = next(e for e in hand.enumerate(seed, graph) if e.actions == ("subdomains",))
    obs = hand.act(ep, "subdomains", {})
    facts = hand.normalize(obs)

    discovered = {e.id for f in facts for e in f.yields}
    # Merged, cleaned (case, wildcard), deduped, and filtered to under the root.
    assert discovered == {"api.example.com", "www.example.com", "mail.example.com"}
    assert "unrelated.org" not in discovered
    # One source failing does not sink the sweep.
    assert obs.raw["sources"]["flaky"].startswith("error:")


def test_get_fingerprints_service_and_technology(stub_server):
    hand = ReconHand()
    get_ep = hand._get_ep("probe.example.com", stub_server)
    obs = hand.act(get_ep, "get", {})
    facts = hand.normalize(obs)

    yielded = [e for f in facts for e in f.yields]
    services = [e for e in yielded if e.kind == "service"]
    techs = [e for e in yielded if e.kind == "technology"]
    assert services and services[0].props["status"] == 200
    # The stub server sends a Server header, so a technology is fingerprinted.
    assert techs


def test_discover_roots_yields_candidates_not_expanded():
    hand = ReconHand(root_search=lambda kw: ["example.com", "example.cn", "1example.com"])
    graph = SituationGraph()
    org = Target(id="example", kind="org")
    graph.add_target(org)

    disc_ep = next(ep for ep in hand.enumerate(org, graph) if ep.actions == ("discover_roots",))
    assert disc_ep.props.get("osint") is True
    facts = hand.normalize(hand.act(disc_ep, "discover_roots", {}))
    candidates = [e for f in facts for e in f.yields]
    assert {c.id for c in candidates} == {"example.com", "example.cn", "1example.com"}
    assert all(c.props["candidate"] for c in candidates)

    # Candidates are recorded but not expanded: no resolve or get entrypoints.
    for c in candidates:
        graph.add_entity(c)
    eps = {ep.id for ep in hand.enumerate(org, graph)}
    assert not any(e.startswith("resolve::") or e.startswith("get::") for e in eps)


def test_osint_discovery_is_authorized_even_with_empty_scope():
    from opfor.engine.scope import Scope

    hand = ReconHand()
    scope = Scope(domain_suffixes=(), max_tier="recon")
    disc_ep = hand._discover_ep("example")
    assert scope.authorize(SituationGraph(), disc_ep, "discover_roots").allowed


_GIT_CHECK = {
    "id": "git-config-exposed",
    "path": "/.git/config",
    "severity": "high",
    "title": "Exposed .git/config",
    "match": {"status": 200, "body_contains": "[core]"},
}


def test_check_fires_finding_on_exposed_git(stub_server):
    hand = ReconHand(checks=[_GIT_CHECK])
    ep = hand._check_ep(stub_server + "/", "probe.example.com", _GIT_CHECK)
    facts = hand.normalize(hand.act(ep, "check", {}))
    findings = [e for f in facts for e in f.yields]
    assert findings and findings[0].kind == "finding"
    assert findings[0].props["severity"] == "high"
    assert findings[0].props["domain"] == "probe.example.com"


def test_check_negative_matcher_kills_html_false_positive():
    dotenv = {
        "id": "dotenv-exposed",
        "match": {
            "status": 200,
            "body_contains": "=",
            "content_type_excludes": "text/html",
            "body_not_contains": ["<html", "<!doctype"],
        },
    }
    hand = ReconHand()
    # A 200 HTML login page (IAP/SPA) that happens to contain "=" must NOT fire.
    html = {
        "status": 200, "url": "https://x/.env", "domain": "x",
        "headers": {"Content-Type": "text/html"},
        "body": "<!doctype html><html>a=b</html>", "check": dotenv,
    }
    assert hand._check_finding(html) is None
    # A genuine key=value .env body fires.
    real = {
        "status": 200, "url": "https://x/.env", "domain": "x",
        "headers": {"Content-Type": "text/plain"},
        "body": "SECRET_KEY=abc\nDB_URL=postgres://x", "check": dotenv,
    }
    assert hand._check_finding(real) is not None


def test_check_clean_when_signature_absent(stub_server):
    miss = {**_GIT_CHECK, "path": "/nope"}
    hand = ReconHand(checks=[miss])
    ep = hand._check_ep(stub_server + "/", "probe.example.com", miss)
    facts = hand.normalize(hand.act(ep, "check", {}))
    assert facts[0].kind == "check-clean"
    assert not [e for f in facts for e in f.yields]


def test_checks_only_enumerated_for_live_services():
    from opfor.model import Service

    hand = ReconHand(subdomain_sources=[], checks=[_GIT_CHECK])
    graph = SituationGraph()
    graph.add_target(_seed())
    # No service yet, no check batch.
    eps = {e.id for e in hand.enumerate(_seed(), graph)}
    assert not any(e.startswith("check-batch::") for e in eps)
    # A live service spawns a check batch covering it.
    graph.add_entity(Service(id="https://x.example.com/", props={"domain": "x.example.com", "status": 200}))
    eps = [e for e in hand.enumerate(_seed(), graph) if e.id.startswith("check-batch::")]
    assert eps and eps[0].props["scope_hosts"] == ["x.example.com"]


def test_resolve_batch_marks_live_and_dead_concurrently():
    def resolver(domain):
        if domain == "live.example.com":
            return ["1.2.3.4"]
        raise OSError("nxdomain")

    hand = ReconHand(resolve_fn=resolver)
    ep = hand._resolve_batch_ep(["live.example.com", "gone.example.com"], 0)
    facts = hand.normalize(hand.act(ep, "resolve_all", {}))
    hosts = {h.props["domain"]: h for f in facts for h in f.yields}
    assert hosts["live.example.com"].props["live"] is True
    assert hosts["live.example.com"].props["ips"] == ["1.2.3.4"]
    assert hosts["gone.example.com"].props["live"] is False


def test_scope_allows_suffix_denies_outsiders_and_high_tiers():
    scope = Scope(domain_suffixes=("example.com",), max_tier="probe")
    graph = SituationGraph()
    hand = ReconHand(subdomain_sources=[])

    inside = hand._get_ep("api.example.com", "https://api.example.com/")
    assert scope.authorize(graph, inside, "get").allowed

    outside = hand._get_ep("evil.com", "https://evil.com/")
    assert not scope.authorize(graph, outside, "get").allowed

    intrusive = Entrypoint(
        id="x", target_id="api.example.com", kind="http", ref="/",
        actions=("exploit",),
        props={"scope_host": "api.example.com", "action_tiers": {"exploit": "intrusive"}},
    )
    assert not scope.authorize(graph, intrusive, "exploit").allowed


def test_recon_loop_org_discovers_candidates_and_expands_confirmed(tmp_path):
    def resolver(domain):
        if domain == "api.confirmed.invalid":
            return ["10.0.0.1"]
        raise OSError("nxdomain")

    hand = ReconHand(
        root_search=lambda kw: ["example.cn", "1example.com"],
        subdomain_sources=[("stub", lambda d: ["api.confirmed.invalid"])],
        resolve_fn=resolver,
    )
    loop = AttackLoop(
        hand=hand,
        playbook="recon",
        scope=Scope(domain_suffixes=("confirmed.invalid",), max_tier="probe"),
        brain=MockBrain(),
        workspace=Workspace(tmp_path / "run"),
        budget=80,
    )
    graph = SituationGraph()
    graph.add_target(Target(id="example", kind="org"))
    graph.add_target(
        Target(id="confirmed.invalid", kind="domain", props={"host": "confirmed.invalid", "is_root": True})
    )
    result = loop.run(graph)

    by_id = {d.id: d.props.get("candidate", False) for d in result.graph.entities("domain")}
    # Candidate roots are recorded, flagged, and never expanded (never resolved).
    assert by_id.get("example.cn") is True
    assert by_id.get("1example.com") is True
    resolved_domains = {h.props["domain"] for h in result.graph.entities("host")}
    assert "example.cn" not in resolved_domains
    # The confirmed root is expanded: subdomain discovered, resolved to a host.
    assert by_id.get("api.confirmed.invalid") is False
    assert any(
        h.props["domain"] == "api.confirmed.invalid" and h.props["live"]
        for h in result.graph.entities("host")
    )
    assert result.done


def test_recon_loop_resolves_then_gates_probes_offline(tmp_path):
    # All names on the reserved .invalid TLD so nothing can touch a real host.
    sources = [("stub", lambda d: ["up.test.invalid", "down.test.invalid"])]

    def resolver(domain):
        if domain == "up.test.invalid":
            return ["10.0.0.1"]
        raise OSError("nxdomain")

    loop = AttackLoop(
        hand=ReconHand(subdomain_sources=sources, resolve_fn=resolver),
        playbook="recon",
        scope=Scope(domain_suffixes=("test.invalid",), max_tier="probe"),
        brain=MockBrain(),
        workspace=Workspace(tmp_path / "run"),
        budget=50,
    )
    graph = SituationGraph()
    graph.add_target(_seed("test.invalid"))
    result = loop.run(graph)

    discovered = {d.id for d in result.graph.entities("domain")}
    assert {"up.test.invalid", "down.test.invalid"} <= discovered
    # Both discovered domains were resolved in the batch, recorded as hosts.
    hosts = {h.props["domain"]: h.props["live"] for h in result.graph.entities("host")}
    assert hosts.get("up.test.invalid") is True
    assert hosts.get("down.test.invalid") is False
    # Only the live one was probed into a service, the dead one never touched.
    probed = {s.props["domain"] for s in result.graph.entities("service")}
    assert probed == {"up.test.invalid"}
    assert result.done

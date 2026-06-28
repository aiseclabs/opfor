from opfor.agent.brain import MockBrain
from opfor.engine.graph import SituationGraph
from opfor.engine.loop import AttackLoop
from opfor.engine.scope import Scope
from opfor.engine.state import Workspace
from opfor.model import Domain, Entrypoint, Target
from opfor.scenarios.recon.hand import ReconHand


def _seed(domain="example.com"):
    return Target(id=domain, kind="domain", props={"host": domain, "is_root": True})


def test_crtsh_yields_in_scope_subdomains_only():
    # crt.sh sometimes lists unrelated certificate names, they must be dropped.
    fetch = lambda d: ["api.example.com", "www.example.com", "x.api.example.com", "unrelated.org"]
    hand = ReconHand(crt_fetch=fetch)
    graph = SituationGraph()
    seed = _seed()
    graph.add_target(seed)

    crt_ep = next(ep for ep in hand.enumerate(seed, graph) if ep.actions == ("crtsh",))
    obs = hand.act(crt_ep, "crtsh", {})
    facts = hand.normalize(obs)

    discovered = {e.id for f in facts for e in f.yields}
    assert discovered == {"api.example.com", "www.example.com", "x.api.example.com"}
    assert "unrelated.org" not in discovered


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


def test_resolve_marks_live_and_dead():
    live = ReconHand(resolve_fn=lambda d: ["1.2.3.4"])
    facts = live.normalize(live.act(live._resolve_ep("live.example.com"), "resolve", {}))
    hosts = [e for f in facts for e in f.yields]
    assert hosts and hosts[0].props["ips"] == ["1.2.3.4"]

    def dead(_):
        raise OSError("nxdomain")

    gone = ReconHand(resolve_fn=dead)
    facts = gone.normalize(gone.act(gone._resolve_ep("gone.example.com"), "resolve", {}))
    assert facts[0].kind == "dns-dead"
    assert not [e for f in facts for e in f.yields]


def test_scope_allows_suffix_denies_outsiders_and_high_tiers():
    scope = Scope(domain_suffixes=("example.com",), max_tier="probe")
    graph = SituationGraph()
    hand = ReconHand(crt_fetch=lambda d: [])

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


def test_recon_loop_resolves_then_gates_probes_offline(tmp_path):
    # All names on the reserved .invalid TLD so nothing can touch a real host.
    fetch = lambda d: ["up.test.invalid", "down.test.invalid"]

    def resolver(domain):
        if domain == "up.test.invalid":
            return ["10.0.0.1"]
        raise OSError("nxdomain")

    loop = AttackLoop(
        hand=ReconHand(crt_fetch=fetch, resolve_fn=resolver),
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
    # Both discovered domains were resolved, surface grew and re-enumerated.
    assert result.graph.is_acted("resolve::up.test.invalid", "resolve")
    assert result.graph.is_acted("resolve::down.test.invalid", "resolve")
    # Only the resolvable one became a host and earned an HTTP probe entrypoint.
    resolved = {h.props["domain"] for h in result.graph.entities("host")}
    assert resolved == {"up.test.invalid"}
    entrypoint_ids = {ep.id for ep in result.graph.entrypoints()}
    assert "get::up.test.invalid" in entrypoint_ids
    assert "get::down.test.invalid" not in entrypoint_ids
    assert result.done

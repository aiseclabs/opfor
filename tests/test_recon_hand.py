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
    hand = ReconHand(crt_fetch=lambda d: [])
    graph = SituationGraph()
    graph.add_target(_seed())
    # A discovered domain whose probe url points at the local stub server.
    graph.add_entity(Domain(id="probe.example.com", props={"url": stub_server}))

    get_ep = next(ep for ep in hand.enumerate(_seed(), graph) if ep.id == "get::probe.example.com")
    obs = hand.act(get_ep, "get", {})
    facts = hand.normalize(obs)

    yielded = [e for f in facts for e in f.yields]
    services = [e for e in yielded if e.kind == "service"]
    techs = [e for e in yielded if e.kind == "technology"]
    assert services and services[0].props["status"] == 200
    # The stub server sends a Server header, so a technology is fingerprinted.
    assert techs


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


def test_recon_loop_grows_surface_offline(tmp_path):
    # Names under the seed root, on the reserved .invalid TLD so the probe GETs
    # cannot reach any real host, they fail fast as NXDOMAIN.
    fetch = lambda d: ["a.test.invalid", "b.test.invalid"]
    loop = AttackLoop(
        hand=ReconHand(crt_fetch=fetch),
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
    assert discovered == {"a.test.invalid", "b.test.invalid"}
    # The surface must actually grow: each discovered domain gets a probe
    # entrypoint, and the loop re-enumerates and acts on it. This is what caught
    # the missing generation bump, discovery alone is not enough.
    entrypoint_ids = {ep.id for ep in result.graph.entrypoints()}
    assert "get::a.test.invalid" in entrypoint_ids
    assert "get::b.test.invalid" in entrypoint_ids
    assert result.graph.is_acted("get::a.test.invalid", "get")
    assert result.graph.is_acted("get::b.test.invalid", "get")
    assert result.done

import urllib.parse

from opfor.agent.brain import MockBrain
from opfor.engine.graph import SituationGraph
from opfor.engine.loop import AttackLoop
from opfor.engine.scope import Scope
from opfor.engine.state import Workspace
from opfor.model import Target
from opfor.scenarios.web.hand import WebHand


def _web_target(base_url):
    host = urllib.parse.urlsplit(base_url).hostname
    return Target(id=base_url, kind="web_host", props={"host": host, "paths": ["/"]})


def test_act_gets_real_response(stub_server):
    hand = WebHand()
    graph = SituationGraph()
    target = _web_target(stub_server)
    graph.add_target(target)
    ep = hand.enumerate(target, graph)[0]
    obs = hand.act(ep, "get", {})
    assert obs.raw["status"] == 200
    assert "admin" in obs.raw["body"]


def test_normalize_discovers_same_host_links_only(stub_server):
    hand = WebHand()
    graph = SituationGraph()
    target = _web_target(stub_server)
    graph.add_target(target)
    ep = hand.enumerate(target, graph)[0]
    obs = hand.act(ep, "get", {})
    facts = hand.normalize(obs)
    discovered = {e.ref for f in facts for e in f.yields}
    # Same-host links are discovered, the offsite link is dropped.
    assert "/admin" in discovered
    assert "/about" in discovered
    assert "/off" not in discovered


def test_web_run_crawls_and_grows_via_loop(stub_server, tmp_path):
    host = urllib.parse.urlsplit(stub_server).hostname
    loop = AttackLoop(
        hand=WebHand(),
        playbook="web recon",
        scope=Scope(hosts=(host,), max_tier="recon"),
        brain=MockBrain(),
        workspace=Workspace(tmp_path / "run"),
        budget=50,
    )
    graph = SituationGraph()
    graph.add_target(_web_target(stub_server))
    result = loop.run(graph)

    refs = {ep.ref for ep in result.graph.entrypoints()}
    # The crawl started at "/" and grew to the linked same-host paths.
    assert {"/", "/admin", "/about"} <= refs
    assert result.done

import tempfile

from opfor.engine.collaborator import Collaborator
from opfor.engine.graph import SituationGraph
from opfor.engine.ledger import Ledger
from opfor.engine.state import Workspace
from opfor.model import Endpoint, Fact
from opfor.runner import _correlate_oob
from opfor.scenarios.apiscan.oob import BlindSsrfPlanner


def _graph_with_collab(base="http://collab"):
    g = SituationGraph()
    g.absorb([Fact(kind="collaborator", about="campaign", data={"base": base})])
    return g


def test_planner_emits_nothing_without_a_collaborator():
    g = SituationGraph()
    g.add_entity(Endpoint(id="GET /x", props={"host": "h", "method": "GET", "path": "/x", "params": ["url"]}))
    assert BlindSsrfPlanner().expand(g) == []


def test_planner_targets_only_url_shaped_params():
    g = _graph_with_collab()
    g.add_entity(Endpoint(id="GET /x", props={"host": "h", "method": "GET", "path": "/x", "params": ["url", "name"]}))
    tasks = BlindSsrfPlanner().expand(g)
    # Evidence-gated: `url` matches ssrf affinity, `name` does not.
    assert len(tasks) == 1
    assert tasks[0].params["candidate"]["param"] == "url"
    assert tasks[0].tier == "intrusive"
    # The injected URL (url-encoded as a query value) points at the collaborator.
    assert "collab" in tasks[0].params["request"]["path"]
    assert tasks[0].params["token"] in tasks[0].params["candidate"]["url"]


def test_correlate_confirms_only_hit_tokens():
    collab = Collaborator().start()
    try:
        g = SituationGraph()
        g.absorb([
            Fact(kind="oob-candidate", about="GET /a", data={"token": "hit1", "endpoint": "GET /a", "param": "url", "host": "h", "url": "http://h/a"}),
            Fact(kind="oob-candidate", about="GET /b", data={"token": "miss1", "endpoint": "GET /b", "param": "url", "host": "h", "url": "http://h/b"}),
        ])
        # Simulate a callback for only the first candidate.
        import urllib.request
        urllib.request.urlopen(collab.url_for("hit1"), timeout=5).read()
        with tempfile.TemporaryDirectory() as d:
            _correlate_oob(g, collab, Ledger(Workspace(d).ledger_file))
    finally:
        collab.stop()
    findings = {f.id for f in g.entities("finding")}
    verdicts = {f.data["finding"]: f.data["verdict"] for f in g.facts() if f.kind == "verdict"}
    assert findings == {"finding:blind-ssrf:GET /a:url"}
    assert verdicts["finding:blind-ssrf:GET /a:url"] == "confirmed"

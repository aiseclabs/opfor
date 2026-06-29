from opfor.engine.graph import SituationGraph
from opfor.engine.ledger import Ledger
from opfor.engine.tasks import Task
from opfor.model import Endpoint
from opfor.report import render
from opfor.scenarios.apiscan.hypothesis import HypothesisExecutor, HypothesisPlanner


def _hyps_for(params):
    ex = HypothesisExecutor()
    task = Task(id="hyp", capability="hypothesize", target="h",
                params={"endpoint": {"id": "GET /x", "path": "/x", "method": "GET", "params": params, "host": "h"}})
    facts = ex.perceive(ex.run(task, None))
    return [e for f in facts for e in f.yields]


def test_hypothesis_marks_evidence_when_param_matches_affinity():
    hyps = {h.props["vuln"]: h for h in _hyps_for(["file"])}
    # `file` is evidence for traversal, not for sqli.
    assert hyps["traversal"].props["evidence_backed"] is True
    assert hyps["traversal"].props["support"] == ["file"]
    assert hyps["sqli"].props["evidence_backed"] is False


def test_hypothesis_all_blind_when_no_param_matches():
    hyps = _hyps_for(["zzz"])
    assert all(h.props["evidence_backed"] is False for h in hyps)


def test_hypothesis_planner_one_task_per_endpoint_then_stops():
    graph = SituationGraph()
    graph.add_entity(Endpoint(id="GET /a", props={"host": "h", "method": "GET", "path": "/a", "params": ["id"]}))
    tasks = HypothesisPlanner().expand(graph)
    assert [t.capability for t in tasks] == ["hypothesize"]
    assert tasks[0].tier == "recon"  # no network, safe tier
    # Record the hypotheses, then the planner does not re-emit.
    ex = HypothesisExecutor()
    graph.absorb(ex.perceive(ex.run(tasks[0], graph)))
    assert HypothesisPlanner().expand(graph) == []


def test_hypothesis_planner_skips_dangerous_endpoints():
    graph = SituationGraph()
    graph.add_entity(Endpoint(id="POST /logout", props={"host": "h", "method": "POST", "path": "/logout"}))
    assert HypothesisPlanner().expand(graph) == []


def test_report_lists_evidence_backed_hypotheses(tmp_path):
    graph = SituationGraph()
    ex = HypothesisExecutor()
    task = Task(id="hyp", capability="hypothesize", target="h",
                params={"endpoint": {"id": "GET /dl", "path": "/dl", "method": "GET", "params": ["file"], "host": "h"}})
    graph.absorb(ex.perceive(ex.run(task, graph)))
    out = render(graph, Ledger(tmp_path / "ledger.jsonl"), stopped_reason="done")
    assert "Exploitation hypotheses (evidence-backed)" in out
    assert "traversal @ GET /dl" in out

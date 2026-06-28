from opfor.agent.brain import Brain, BrainContext, ModelBrain, Move
from opfor.engine.graph import SituationGraph
from opfor.engine.loop import AttackLoop
from opfor.engine.scope import Scope
from opfor.engine.state import Workspace
from opfor.model import Entrypoint, Observation, Target
from opfor.plugins.base import Hand


def test_model_brain_parses_move_and_findings():
    # The complete() seam returns raw model text, here a canned JSON object.
    reply = """Sure, here is my decision:
    {"stop": false, "judgment": "admin panel answered 200 with no auth",
     "entrypoint_id": "get::admin.example.com", "action": "get", "params": {},
     "note": "follow up", "findings": [
        {"title": "Exposed admin panel", "severity": "high",
         "domain": "admin.example.com", "evidence": "200 OK, no auth header"}]}
    """
    brain = ModelBrain(lambda prompt: reply)
    ctx = BrainContext(graph=SituationGraph(), live_entrypoints=(), recent=(), playbook="x")
    move = brain.decide(ctx)
    assert move.action == "get"
    assert move.entrypoint_id == "get::admin.example.com"
    assert len(move.findings) == 1
    assert move.findings[0]["severity"] == "high"


def test_model_brain_prompt_includes_graph_summary():
    brain = ModelBrain(lambda p: '{"judgment": "ok", "stop": true}')
    graph = SituationGraph()
    captured = {}
    spy = ModelBrain(lambda p: captured.setdefault("prompt", p) or '{"judgment":"ok","stop":true}')
    ctx = BrainContext(graph=graph, live_entrypoints=(), recent=(), playbook="PB")
    spy.decide(ctx)
    assert "What is known so far" in captured["prompt"]
    assert "PB" in captured["prompt"]


class _FindingBrain(Brain):
    """Asserts one finding, then stops. Stands in for a model that judged."""

    def decide(self, context: BrainContext) -> Move:
        return Move(
            stop=True,
            judgment="done",
            findings=[{"title": "Leaked map", "severity": "medium", "domain": "x.example.com"}],
        )


class _NoopHand(Hand):
    name = "noop"

    def enumerate(self, target, graph):
        return []

    def act(self, entrypoint, action, params):
        return Observation(entrypoint_id=entrypoint.id, action=action)

    def normalize(self, observation):
        return []


def test_loop_records_brain_findings(tmp_path):
    loop = AttackLoop(
        hand=_NoopHand(),
        playbook="x",
        scope=Scope(hosts=("h",), max_tier="recon"),
        brain=_FindingBrain(),
        workspace=Workspace(tmp_path / "run"),
        budget=10,
    )
    graph = SituationGraph()
    graph.add_target(Target(id="t", kind="web_host", props={"host": "h"}))
    result = loop.run(graph)

    findings = result.graph.entities("finding")
    assert len(findings) == 1
    assert findings[0].props["severity"] == "medium"
    assert any(e["kind"] == "finding" for e in loop.ledger.entries())

from opfor.agent.brain import BrainContext, HybridBrain, ModelBrain
from opfor.engine.graph import SituationGraph
from opfor.model import Entrypoint


def _ep(eid, action, tier):
    return Entrypoint(
        id=eid, target_id="t", kind="k", ref="/" + eid, actions=(action,),
        props={"action_tiers": {action: tier}},
    )


def _ctx(graph, eps):
    return BrainContext(graph=graph, live_entrypoints=tuple(eps), recent=(), playbook="p")


def test_hybrid_runs_recon_without_calling_model():
    calls = {"n": 0}

    def complete(prompt):
        calls["n"] += 1
        return '{"judgment": "ok", "stop": true}'

    brain = HybridBrain(ModelBrain(complete))
    graph = SituationGraph()
    recon_ep = _ep("resolve::a", "resolve", "recon")
    probe_ep = _ep("get::a", "get", "probe")

    # While a recon action is unacted, the model is never consulted.
    move = brain.decide(_ctx(graph, [recon_ep, probe_ep]))
    assert move.action == "resolve"
    assert calls["n"] == 0


def test_hybrid_defers_to_model_once_recon_is_exhausted():
    calls = {"n": 0}

    def complete(prompt):
        calls["n"] += 1
        return '{"judgment": "mapped", "stop": true, "findings": []}'

    brain = HybridBrain(ModelBrain(complete))
    graph = SituationGraph()
    probe_ep = _ep("get::a", "get", "probe")
    graph.mark_acted("resolve::a", "resolve")  # recon already done

    move = brain.decide(_ctx(graph, [probe_ep]))
    assert calls["n"] == 1
    assert move.stop

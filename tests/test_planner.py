"""Guards for the planner primitives, especially the model-driven seam.

ModelPlanner is the engine's reusable hook for open-ended phases: a function that
may consult a model to propose tasks. The model only proposes; these tests pin
that contract with a stub model, no live call.
"""

from __future__ import annotations

from opfor.agent.planner import CompositePlanner, FunctionPlanner, ModelPlanner
from opfor.engine.graph import SituationGraph
from opfor.engine.tasks import Task
from opfor.model import Target


def _graph_with(*targets: Target) -> SituationGraph:
    g = SituationGraph()
    for t in targets:
        g.add_target(t)
    return g


def test_model_planner_passes_complete_to_the_rule():
    seen = {}

    def rule(graph, complete):
        # The rule may call the model to decide; here it just records the seam.
        seen["answer"] = complete("what next?")
        return [Task(id="t1", capability="cap", target="x", scope_host="h")]

    planner = ModelPlanner(lambda prompt: "the model says go", rule)
    tasks = planner.expand(_graph_with())

    assert seen["answer"] == "the model says go"
    assert [t.id for t in tasks] == ["t1"]


def test_model_planner_only_proposes_no_side_effects_on_graph():
    # The planner must not write the graph; it returns tasks, the shell acts.
    g = _graph_with(Target(id="a", kind="mock", props={"host": "h"}))

    def rule(graph, complete):
        return [Task(id="t", capability="c", target="a", scope_host="h")]

    ModelPlanner(lambda p: "x", rule).expand(g)
    assert not g.entities("finding")
    assert len(list(g.targets())) == 1


def test_composite_merges_function_and_model_planners():
    g = _graph_with(Target(id="a", kind="mock", props={"host": "h"}))
    fn = FunctionPlanner(lambda graph: [Task(id="f", capability="c", target="a", scope_host="h")])
    md = ModelPlanner(lambda p: "x", lambda graph, complete: [
        Task(id="m", capability="c", target="a", scope_host="h")
    ])
    tasks = CompositePlanner([fn, md]).expand(g)
    assert {t.id for t in tasks} == {"f", "m"}

"""Record exploitation hypotheses on the blackboard, the evidence layer.

For each discovered endpoint, conjecture which vuln classes are plausible and why
(a parameter name matching a probe's affinity is the supporting evidence). The
hypotheses are recorded as graph entities so the evidence behind any intrusive
test is auditable, and so the report can show evidence-backed work apart from
blind fuzzing. No network: this only structures cheap signals already on the
graph, the planner that fuzzes uses the same evidence to score confidence.
"""

from __future__ import annotations

from opfor.agent.planner import Planner
from opfor.engine.graph import SituationGraph
from opfor.engine.tasks import Task
from opfor.model import Fact, Hypothesis, Observation
from opfor.plugins.base import Executor
from opfor.scenarios.apiscan.endpoint_vuln import _DANGEROUS, FUZZ_PROBES


class HypothesisExecutor(Executor):
    capability = "hypothesize"

    def run(self, task, graph) -> Observation:
        return Observation(entrypoint_id=task.id, action="hypothesize", raw={"endpoint": task.params["endpoint"]})

    def perceive(self, observation) -> list[Fact]:
        ep = observation.raw["endpoint"]
        inputs = list(ep.get("params") or []) + list(ep.get("body_params") or [])
        hyps = []
        for probe in FUZZ_PROBES:
            support = [p for p in inputs if any(a in str(p).lower() for a in probe.get("affinity", []))]
            hyps.append(Hypothesis(
                id=f"hyp:{ep['id']}:{probe['id']}",
                props={
                    "endpoint": ep["id"], "vuln": probe["id"], "support": support,
                    "evidence_backed": bool(support),
                },
            ))
        backed = sum(1 for h in hyps if h.props["evidence_backed"])
        return [Fact(kind="hypotheses", about=ep["id"], data={"endpoint": ep["id"], "evidence_backed": backed, "total": len(hyps)}, yields=tuple(hyps))]


class HypothesisPlanner(Planner):
    """One hypothesize task per endpoint, once. No network, so recon tier."""

    def expand(self, graph: SituationGraph) -> list[Task]:
        done = {h.props.get("endpoint") for h in graph.entities("hypothesis")}
        tasks: list[Task] = []
        for ep in graph.entities("endpoint"):
            path = ep.props.get("path", "/")
            if ep.id in done or any(bad in path.lower() for bad in _DANGEROUS):
                continue
            host = ep.props.get("host")
            tasks.append(Task(
                id=f"hyp:{ep.id}", capability="hypothesize", target=host,
                params={"endpoint": {
                    "id": ep.id, "path": path, "method": ep.props.get("method", "GET"),
                    "params": ep.props.get("params"), "body_params": ep.props.get("body_params"), "host": host,
                }},
                tier="recon", scope_host=host,
            ))
        return tasks


def hypothesis_executors() -> dict[str, Executor]:
    return {"hypothesize": HypothesisExecutor()}

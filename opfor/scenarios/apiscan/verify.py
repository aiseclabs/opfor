"""Verification-as-currency: a finding is real only when re-proven.

The detection stage proposes a finding from a non-reflective success signal. The
verify stage re-executes that finding's proof recipe (the exact request) and
re-applies the same matcher: if the signal reproduces, the finding is confirmed;
if it does not, it was a fluke and is ruled a false positive. Findings that carry
no replayable proof (e.g. multi-step JWT, header-hygiene checks) are left
unverifiable for the model triage to advise on.

This moves success judgment off the model's opinion of a finding and onto a
concrete oracle (the AIxCC "PoV-as-currency" idea), without putting any attack
logic in the executor: the proof recipe is data carried by the finding.
"""

from __future__ import annotations

from opfor.agent.planner import Planner
from opfor.engine.graph import SituationGraph
from opfor.engine.tasks import Task
from opfor.model import Fact, Observation
from opfor.plugins.base import Executor
from opfor.scenarios.apiscan.executors import _do, _matches


class VerifyExecutor(Executor):
    capability = "verify"

    def run(self, task, graph) -> Observation:
        proof = task.params["proof"]
        r = proof.get("request", {})
        raw = _do(
            proof["base_url"], r.get("method", "GET").upper(), r.get("path", "/"),
            body=r.get("body"), content_type=r.get("content_type"),
            headers=r.get("headers"), follow_redirects=r.get("follow_redirects", True),
        )
        reproved = _matches(proof.get("match", {}), raw)
        return Observation(
            entrypoint_id=task.id, action="verify",
            raw={
                "finding": task.params["finding_id"],
                "reproved": reproved,
                "status": raw.get("status"),
                "error": raw.get("error"),
                "snippet": (raw.get("body") or "")[:240],
            },
        )

    def perceive(self, observation) -> list[Fact]:
        raw = observation.raw
        if raw.get("reproved"):
            verdict, reason = "confirmed", "re-executed the PoC, the success signal reproduced"
        else:
            verdict, reason = "false_positive", "re-execution did not reproduce the success signal"
        return [Fact(
            kind="verdict", about=raw["finding"],
            data={"finding": raw["finding"], "verdict": verdict, "reason": reason, "status": raw.get("status")},
        )]


class VerifyPlanner(Planner):
    """Emit one verify task per finding that carries a proof recipe and has no
    verdict yet. Findings without a proof recipe stay unverifiable."""

    def expand(self, graph: SituationGraph) -> list[Task]:
        judged = {f.data.get("finding") for f in graph.facts() if f.kind == "verdict"}
        tasks: list[Task] = []
        for fnd in graph.entities("finding"):
            proof = fnd.props.get("proof")
            if not proof or fnd.id in judged:
                continue
            tasks.append(Task(
                id=f"verify:{fnd.id}",
                capability="verify",
                target=proof.get("scope_host") or fnd.props.get("domain"),
                params={"finding_id": fnd.id, "proof": proof},
                tier=proof.get("tier", "probe"),
                scope_host=proof.get("scope_host"),
            ))
        return tasks


def verify_executors() -> dict[str, Executor]:
    return {"verify": VerifyExecutor()}

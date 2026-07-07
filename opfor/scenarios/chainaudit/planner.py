"""The chainaudit planner, a deterministic two-stage DAG per contract.

For each authorized EVM contract target it emits a fetch task, then, only once a
source-fetch-succeeded fact is on the graph, a review task. Gating on facts, not
on task deps, is deliberate and load-bearing: the control shell marks a task done
whether it succeeded or failed, so a dep would let review run after a failed
fetch. Reading the success fact is the only way to stop a failed stage from
unlocking the next one, and it is also what lets a resume skip completed stages.
"""

from __future__ import annotations

from opfor.agent.planner import Planner
from opfor.engine.graph import SituationGraph
from opfor.engine.tasks import Task


class ChainauditPlanner(Planner):
    def expand(self, graph: SituationGraph) -> list[Task]:
        fetch_ok = self._about(graph, "chainaudit_source_fetch_succeeded")
        fetch_failed = self._about(graph, "chainaudit_source_fetch_failed")
        reviewed = self._about(graph, "chainaudit_review_succeeded") | self._about(
            graph, "chainaudit_review_failed"
        )

        tasks: list[Task] = []
        for target in graph.targets():
            if target.kind != "evm_contract":
                continue
            tid = target.id
            # Stage 1: fetch source, until the graph records the fetch outcome.
            if tid not in fetch_ok and tid not in fetch_failed:
                tasks.append(Task(
                    id=f"chainaudit:fetch:{tid}",
                    capability="chainaudit_fetch_source",
                    target=tid, tier="recon", scope_resource=tid,
                ))
                continue
            # Stage 2: review, only after a successful fetch and only once.
            if tid in fetch_ok and tid not in reviewed:
                tasks.append(Task(
                    id=f"chainaudit:review:{tid}",
                    capability="chainaudit_review_source",
                    target=tid, tier="recon", scope_resource=tid,
                ))
        return tasks

    @staticmethod
    def _about(graph: SituationGraph, kind: str) -> set[str]:
        return {f.about for f in graph.facts() if f.kind == kind}

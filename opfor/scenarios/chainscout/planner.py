"""The chainscout planner: discover, enrich, then escalate each candidate.

A deterministic, fact-gated pipeline per the recon playbook:

1. For each `evm_chain` seed, run the DeFiLlama discovery once.
2. For each discovered `evm_contract`, run the two enrichments (GoPlus risk,
   Etherscan meta), each once.
3. Once a contract has both enrichments recorded, escalate it to one assess
   task, which mints the candidate Finding for triage.

Gating is on facts, not task deps, and this is load-bearing: the control shell
marks a task done whether it succeeded or failed, so a dep would let assess run
off a half-enriched contract. Reading the outcome fact (success *or* failure) is
what sequences the stages and what lets a resume skip finished work.

The planner sets each candidate's priority band (`severity`) from the risk and
meta facts, per the rubric in `knowledge/scoring.md`. That is a prioritization
call, which is the planner's job; it is only a hint. The authoritative real /
false-positive verdict is triage's, downstream, never asserted here.
"""

from __future__ import annotations

from opfor.agent.planner import Planner
from opfor.engine.graph import SituationGraph
from opfor.engine.tasks import Task

# Flags that, if GoPlus trips them, mark a contract as high priority: they are
# the owner-controls-your-funds class (rug / trap), the scariest to leave unaudited.
_HIGH_RISK_FLAGS = frozenset({
    "is_honeypot", "hidden_owner", "can_take_back_ownership", "selfdestruct",
    "owner_change_balance", "cannot_sell_all",
})


class ChainscoutPlanner(Planner):
    def expand(self, graph: SituationGraph) -> list[Task]:
        seeded = self._about(graph, "chainscout_seeded") | self._about(graph, "chainscout_seed_failed")
        risk_done = self._about(graph, "chainscout_risk") | self._about(graph, "chainscout_risk_failed")
        meta_done = self._about(graph, "chainscout_meta") | self._about(graph, "chainscout_meta_failed")
        assessed = self._about(graph, "chainscout_candidate")

        tasks: list[Task] = []
        for target in graph.targets():
            if target.kind == "evm_chain":
                if target.id not in seeded:
                    tasks.append(self._osint(
                        f"chainscout:seed:{target.id}", "chainscout_seed", target.id))
                continue
            if target.kind != "evm_contract":
                continue
            tid = target.id
            if tid not in risk_done:
                tasks.append(self._osint(f"chainscout:risk:{tid}", "chainscout_risk", tid))
            if tid not in meta_done:
                tasks.append(self._osint(f"chainscout:meta:{tid}", "chainscout_meta", tid))
            # Escalate only once both enrichments have a recorded outcome.
            if tid in risk_done and tid in meta_done and tid not in assessed:
                tasks.append(self._osint(
                    f"chainscout:assess:{tid}", "chainscout_assess", tid,
                    params={"severity": self._severity(graph, tid)},
                ))
        return tasks

    def _severity(self, graph: SituationGraph, target_id: str) -> str:
        """Priority band for a candidate, from its risk and meta facts.

        Rubric (documented in knowledge/scoring.md): a high-risk flag -> high; an
        unverified contract (no source to audit, opaque) -> medium; otherwise low.
        Value (TVL) rides along on the finding as a separate axis and does not
        change the band, so risk and value stay independent in the report.
        """
        risk = self._latest(graph, "chainscout_risk", target_id)
        meta = self._latest(graph, "chainscout_meta", target_id)
        flags = set((risk or {}).get("risk_flags", []))
        if flags & _HIGH_RISK_FLAGS:
            return "high"
        if meta is not None and meta.get("verified") is False:
            return "medium"
        return "low"

    @staticmethod
    def _osint(task_id: str, capability: str, target_id: str, params: dict | None = None) -> Task:
        # Passive read of a public API about a public contract: osint, recon tier.
        return Task(
            id=task_id, capability=capability, target=target_id,
            tier="recon", osint=True, params=params or {},
        )

    @staticmethod
    def _about(graph: SituationGraph, kind: str) -> set[str]:
        return {f.about for f in graph.facts() if f.kind == kind}

    @staticmethod
    def _latest(graph: SituationGraph, kind: str, about: str) -> dict | None:
        found = None
        for f in graph.facts():
            if f.kind == kind and f.about == about:
                found = f.data
        return found

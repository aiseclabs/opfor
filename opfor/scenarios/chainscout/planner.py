"""The chainscout planner: discover, enrich, then escalate each candidate.

A deterministic, fact-gated pipeline over the recon playbook:

1. For each `evm_chain` seed, run the Moralis holder discovery once.
2. For each discovered `evm_contract`, run the three enrichments (age, meta,
   risk), each once.
3. Once a contract has all three recorded, escalate it to one assess task, which
   mints the candidate Finding for triage.

Gating is on facts, not task deps, and this is load-bearing: the control shell
marks a task done whether it succeeded or failed, so a dep would let assess run
off a half-enriched contract. Reading the outcome fact (success *or* failure) is
what sequences the stages and what lets a resume skip finished work.

The planner sets each candidate's priority band (`severity`) and its "why"
signals, following the recency-first rubric in `knowledge/scoring.md` and the
template denylist in `knowledge/templates.yaml`. That is a prioritization call,
which is the planner's job; it is only a hint. The authoritative real /
false-positive verdict is triage's, downstream, never asserted here. No executor
reads this rubric or that denylist.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from opfor.agent.planner import Planner
from opfor.engine.graph import SituationGraph
from opfor.engine.tasks import Task

# Flags that, if GoPlus trips them, force a candidate to high priority: the
# owner-controls-your-funds class (rug / trap), scariest to leave unaudited.
_HIGH_RISK_FLAGS = frozenset({
    "is_honeypot", "hidden_owner", "can_take_back_ownership", "selfdestruct",
    "owner_change_balance", "cannot_sell_all",
})

_TEMPLATES = Path(__file__).resolve().parent / "knowledge" / "templates.yaml"


class ChainscoutPlanner(Planner):
    def __init__(self, templates_path: Path | None = None) -> None:
        # The template denylist is knowledge (data), loaded once. Fail loud if it
        # is missing: without it the planner cannot de-prioritize standard code.
        path = templates_path or _TEMPLATES
        spec = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        self._template_names = [str(n).lower() for n in (spec.get("names") or [])]
        self._template_impls = {str(i).lower() for i in (spec.get("implementations") or [])}

    def expand(self, graph: SituationGraph) -> list[Task]:
        seeded = self._about(graph, "chainscout_seeded") | self._about(graph, "chainscout_seed_failed")
        age_done = self._about(graph, "chainscout_age") | self._about(graph, "chainscout_age_failed")
        meta_done = self._about(graph, "chainscout_meta") | self._about(graph, "chainscout_meta_failed")
        risk_done = self._about(graph, "chainscout_risk") | self._about(graph, "chainscout_risk_failed")
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
            if tid not in age_done:
                tasks.append(self._osint(f"chainscout:age:{tid}", "chainscout_age", tid))
            if tid not in meta_done:
                tasks.append(self._osint(f"chainscout:meta:{tid}", "chainscout_meta", tid))
            if tid not in risk_done:
                tasks.append(self._osint(f"chainscout:risk:{tid}", "chainscout_risk", tid))
            # Escalate only once all three enrichments have a recorded outcome.
            if {tid} <= age_done & meta_done & risk_done and tid not in assessed:
                severity, signals = self._classify(graph, tid)
                tasks.append(self._osint(
                    f"chainscout:assess:{tid}", "chainscout_assess", tid,
                    params={"severity": severity, "signals": signals}))
        return tasks

    def _classify(self, graph: SituationGraph, target_id: str) -> tuple[str, list[str]]:
        """Priority band and "why" signals for a candidate, recency-first.

        Rubric (documented in knowledge/scoring.md):
        - a high-risk GoPlus flag -> high (rug / trap dominates everything);
        - else a known template (knowledge/templates.yaml) -> low (standard,
          audited code, de-prioritized);
        - else custom logic deployed within the recency window -> high (fresh
          unaudited code holding value is where exploits actually land);
        - else custom but older -> medium.
        Value is a gate at the seed, not a band input, so it never inflates
        priority; it rides on the finding for the operator to weigh.
        """
        risk = self._latest(graph, "chainscout_risk", target_id) or {}
        meta = self._latest(graph, "chainscout_meta", target_id) or {}
        age = self._latest(graph, "chainscout_age", target_id) or {}

        flags = set(risk.get("risk_flags", []))
        name = meta.get("contract_name", "")
        impl = meta.get("implementation", "")
        verified = meta.get("verified")
        fresh = bool(age.get("fresh"))
        age_days = age.get("age_days")
        template = self._is_template(name, impl)

        signals: list[str] = []
        if isinstance(age_days, int):
            signals.append(f"{'fresh' if fresh else 'aged'}:{age_days}d")
        signals.append(f"template:{name or impl}" if template else "custom")
        if verified is False:
            signals.append("unverified")
        if meta.get("is_proxy"):
            signals.append("proxy")
        hits = flags & _HIGH_RISK_FLAGS
        if hits:
            signals.append("flag:" + ",".join(sorted(hits)))

        if hits:
            return "high", signals
        if template:
            return "low", signals
        if fresh:
            return "high", signals
        return "medium", signals

    def _is_template(self, name: str, impl: str) -> bool:
        low = (name or "").lower()
        if any(t in low for t in self._template_names):
            return True
        return (impl or "").lower() in self._template_impls

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

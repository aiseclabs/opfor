"""The brain, the only place attack decisions and success judgments are made.

Invariant 2: the engine never decides whether an act succeeded, the brain does,
from the raw reaction. The brain reads the situation graph and the scenario
playbook, then returns one Move, which entrypoint and action to try next, plus
its judgment of what the recent raw observations mean. MockBrain is a
deterministic policy for offline tests. ModelBrain is the real seam, it asks a
model and parses a single JSON object back.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable

from opfor.engine.graph import SituationGraph
from opfor.engine.scope import tier_rank
from opfor.json_parse import require_object
from opfor.model import Entrypoint, Observation


@dataclass(frozen=True, kw_only=True)
class Move:
    """One decision from the brain.

    findings are the brain's judgments about what it has seen, for example an
    exposed admin panel or a leaked internal map. The engine records them but
    never invents them, only the brain decides what is a finding.
    """

    stop: bool = False
    judgment: str = ""
    entrypoint_id: str | None = None
    action: str | None = None
    params: dict[str, Any] = field(default_factory=dict)
    note: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True, kw_only=True)
class BrainContext:
    """Everything the brain is allowed to see when it decides."""

    graph: SituationGraph
    live_entrypoints: tuple[Entrypoint, ...]
    recent: tuple[Observation, ...]
    playbook: str


class Brain(ABC):
    @abstractmethod
    def decide(self, context: BrainContext) -> Move:
        """Judge the recent raw observations and choose the next move."""


class MockBrain(Brain):
    """A deterministic policy, enough to walk the loop without a model.

    It prefers the least intrusive unacted action on the first live entrypoint,
    and it stops when nothing pokeable remains. Its judgment is a plain reading
    of the raw reactions, which is exactly the call the engine refuses to make.
    """

    name = "mock"

    def decide(self, context: BrainContext) -> Move:
        judgment = self._judge(context.recent)
        if not context.live_entrypoints:
            return Move(stop=True, judgment=judgment, note="no live entrypoints remain")
        for ep in context.live_entrypoints:
            action = self._next_action(ep, context.graph)
            if action is not None:
                return Move(
                    judgment=judgment,
                    entrypoint_id=ep.id,
                    action=action,
                    params={},
                    note=f"poke {ep.ref} via {action}",
                )
        return Move(stop=True, judgment=judgment, note="every action exhausted")

    def _next_action(self, ep: Entrypoint, graph: SituationGraph) -> str | None:
        tiers = ep.props.get("action_tiers", {})
        unacted = [a for a in ep.actions if not graph.is_acted(ep.id, a)]
        if not unacted:
            return None
        return sorted(unacted, key=lambda a: tier_rank(tiers.get(a, "intrusive")))[0]

    def _judge(self, recent: tuple[Observation, ...]) -> str:
        if not recent:
            return "no reactions observed yet"
        bits = []
        for obs in recent:
            status = obs.raw.get("status")
            bits.append(f"{obs.action} on {obs.entrypoint_id} returned status {status}")
        return "; ".join(bits)


# JSON shape the model must return, kept here next to the parser that enforces it.
MOVE_SHAPE = (
    '{"stop": false, "judgment": "what the recent raw reactions mean", '
    '"entrypoint_id": "id or null", "action": "action name or null", '
    '"params": {}, "note": "short reason", '
    '"findings": [{"title": "...", "severity": "info|low|medium|high|critical", '
    '"domain": "...", "evidence": "..."}]}'
)


class ModelBrain(Brain):
    """Real brain. Renders a prompt, asks a model, parses one JSON Move."""

    name = "model"

    def __init__(self, complete: Callable[[str], str]) -> None:
        # complete maps a prompt to raw model text. The provider is wired by the
        # caller, so this class stays free of any vendor dependency.
        self._complete = complete

    def decide(self, context: BrainContext) -> Move:
        prompt = self._render(context)
        text = self._complete(prompt)
        obj = require_object(text, required_key="judgment")
        findings = obj.get("findings") or []
        return Move(
            stop=bool(obj.get("stop", False)),
            judgment=str(obj.get("judgment", "")),
            entrypoint_id=obj.get("entrypoint_id") or None,
            action=obj.get("action") or None,
            params=obj.get("params") or {},
            note=str(obj.get("note", "")),
            findings=findings if isinstance(findings, list) else [],
        )

    def _render(self, context: BrainContext) -> str:
        live = "\n".join(
            f'- entrypoint_id="{ep.id}" ref={ep.ref} actions={list(ep.actions)}'
            for ep in context.live_entrypoints[:60]
        ) or "- none"
        recent = "\n".join(
            f"- {obs.action} on {obs.entrypoint_id} raw={obs.raw}"
            for obs in context.recent
        ) or "- none"
        return (
            f"{context.playbook}\n\n"
            "You are choosing the next offensive action. Judge the recent raw "
            "reactions yourself, the engine will not. Record anything notable as "
            "a finding. Set entrypoint_id to the exact quoted value from the list "
            "below, nothing more.\n\n"
            f"What is known so far:\n{self._graph_summary(context.graph)}\n\n"
            f"Live entrypoints (first 60):\n{live}\n\n"
            f"Recent raw observations:\n{recent}\n\n"
            f"Respond with exactly one JSON object like:\n{MOVE_SHAPE}"
        )

    def _graph_summary(self, graph: SituationGraph) -> str:
        domains = graph.entities("domain")
        hosts = graph.entities("host")
        services = graph.entities("service")
        techs = graph.entities("technology")
        lines = [
            f"counts: domains={len(domains)} resolved_hosts={len(hosts)} "
            f"services={len(services)} technologies={len(techs)}"
        ]
        for s in list(services)[:20]:
            lines.append(f"service {s.id} status={s.props.get('status')}")
        for t in list(techs)[:20]:
            lines.append(f"tech {t.props.get('name')} on {t.props.get('on')}")
        return "\n".join(lines)

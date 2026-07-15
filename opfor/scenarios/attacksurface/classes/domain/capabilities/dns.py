"""ENRICH-phase DNS resolution capability."""

from __future__ import annotations

from opfor.core import Capability, Done, Fact, Failed, Outcome, Phase, Task, World
from opfor.scenarios.attacksurface.classes.domain.types import Resolved


class ResolveDomain(Capability):
    """ENRICH: resolve a domain to its addresses, or mark it dangling."""

    name = "domain_resolve"
    phase = Phase.ENRICH

    def __init__(self, resolve_fn) -> None:
        self._resolve = resolve_fn

    def run(self, task: Task, world: World) -> Outcome:
        name = world.node(task.node).payload.name
        try:
            result = self._resolve(name)
        except Exception as exc:
            return Failed(reason=f"resolve {type(exc).__name__}: {exc}")
        payload = Resolved(resolvable=bool(result["resolvable"]),
                           addresses=tuple(result.get("addresses", ())),
                           cnames=tuple(result.get("cnames", ())))
        return Done(facts=(Fact(kind="resolved", about=task.node, payload=payload),))

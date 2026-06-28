"""The situation graph, the live picture of what we know and can reach.

Constraint 1 from the architecture: the set of pokeable entrypoints is computed
from current state, not enumerated once at the start. Owning a box or capturing
a credential grows new entrypoints. So the graph is a core component, not a
convenience cache. It exposes the entrypoints that are still worth poking right
now, and it signals when the reachable surface may have changed so the loop
re-enumerates.
"""

from __future__ import annotations

from typing import Iterable

from opfor.model import (
    Credential,
    Entrypoint,
    Fact,
    Identity,
    Target,
    entity_from_dict,
    entity_kind,
    entity_to_dict,
)

# Adding one of these kinds may unlock new entrypoints, so it bumps the
# generation counter and prompts the loop to re-enumerate.
_SURFACE_CHANGING = {"target", "credential", "identity", "artifact"}


class SituationGraph:
    """Entities keyed by kind and id, plus the facts learned about them."""

    def __init__(self) -> None:
        self._entities: dict[str, dict[str, object]] = {}
        self._facts: list[Fact] = []
        # (entrypoint_id, action) pairs already performed, so a live entrypoint
        # is one that still has an unacted action.
        self._acted: set[tuple[str, str]] = set()
        # Bumped whenever the reachable surface may have changed.
        self._generation: int = 0

    # --- entities ---------------------------------------------------------

    def add_entity(self, entity: object) -> bool:
        """Add an entity, idempotent by id. Return True if it was new."""
        kind = entity_kind(entity)
        bucket = self._entities.setdefault(kind, {})
        ident = getattr(entity, "id")
        if ident in bucket:
            return False
        bucket[ident] = entity
        if kind in _SURFACE_CHANGING:
            self._generation += 1
        return True

    def add_target(self, target: Target) -> bool:
        return self.add_entity(target)

    def entities(self, kind: str) -> tuple[object, ...]:
        return tuple(self._entities.get(kind, {}).values())

    def targets(self) -> tuple[Target, ...]:
        return self.entities("target")  # type: ignore[return-value]

    def entrypoints(self) -> tuple[Entrypoint, ...]:
        return self.entities("entrypoint")  # type: ignore[return-value]

    def credentials(self) -> tuple[Credential, ...]:
        return self.entities("credential")  # type: ignore[return-value]

    def identities(self) -> tuple[Identity, ...]:
        return self.entities("identity")  # type: ignore[return-value]

    # --- enumeration results and growth ----------------------------------

    def merge_entrypoints(self, entrypoints: Iterable[Entrypoint]) -> int:
        """Fold freshly enumerated entrypoints in, return how many were new."""
        added = 0
        for ep in entrypoints:
            if self.add_entity(ep):
                added += 1
        return added

    def absorb(self, facts: Iterable[Fact]) -> int:
        """Record facts and merge any entities they yield. Return new-entity count."""
        added = 0
        for fact in facts:
            self._facts.append(fact)
            for entity in fact.yields:
                if self.add_entity(entity):
                    added += 1
        return added

    def facts(self) -> tuple[Fact, ...]:
        return tuple(self._facts)

    # --- liveness ---------------------------------------------------------

    def mark_acted(self, entrypoint_id: str, action: str) -> None:
        self._acted.add((entrypoint_id, action))

    def is_acted(self, entrypoint_id: str, action: str) -> bool:
        return (entrypoint_id, action) in self._acted

    def live_entrypoints(self) -> tuple[Entrypoint, ...]:
        """Entrypoints that still have at least one unacted action right now.

        This is recomputed from current state on every call, so newly grown
        entrypoints become live the moment they enter the graph.
        """
        live = []
        for ep in self.entrypoints():
            if any(not self.is_acted(ep.id, a) for a in ep.actions):
                live.append(ep)
        return tuple(live)

    @property
    def generation(self) -> int:
        """Monotonic counter, bumped when the reachable surface may change."""
        return self._generation

    # --- serialization for checkpoint and resume -------------------------

    def to_dict(self) -> dict:
        return {
            "entities": [
                entity_to_dict(e)
                for bucket in self._entities.values()
                for e in bucket.values()
            ],
            "facts": [self._fact_to_dict(f) for f in self._facts],
            "acted": [list(pair) for pair in sorted(self._acted)],
            "generation": self._generation,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SituationGraph":
        graph = cls()
        for ed in data.get("entities", []):
            graph.add_entity(entity_from_dict(ed))
        for fd in data.get("facts", []):
            graph._facts.append(cls._fact_from_dict(fd))
        graph._acted = {tuple(p) for p in data.get("acted", [])}
        # Restore the saved generation, after adds bumped it during reload.
        graph._generation = data.get("generation", graph._generation)
        return graph

    @staticmethod
    def _fact_to_dict(fact: Fact) -> dict:
        return {
            "kind": fact.kind,
            "about": fact.about,
            "data": fact.data,
            "yields": [entity_to_dict(e) for e in fact.yields],
        }

    @staticmethod
    def _fact_from_dict(data: dict) -> Fact:
        return Fact(
            kind=data["kind"],
            about=data["about"],
            data=data.get("data", {}),
            yields=tuple(entity_from_dict(e) for e in data.get("yields", [])),
        )

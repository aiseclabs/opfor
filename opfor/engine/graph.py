"""The situation graph, the blackboard: the live picture of what we know.

The single, persisted source of truth. All long-horizon state lives here, keyed
by entity kind and id. The pokeable surface is computed from current state, not
enumerated once at the start: capturing a credential or discovering a service
adds entities, and the planner re-derives the next tasks from them each round, so
the surface grows live and data-driven.
"""

from __future__ import annotations

from typing import Iterable

from opfor.model import (
    Credential,
    Identity,
    Fact,
    Target,
    entity_from_dict,
    entity_kind,
    entity_to_dict,
)


class SituationGraph:
    """Entities keyed by kind and id, plus the facts learned about them."""

    def __init__(self) -> None:
        self._entities: dict[str, dict[str, object]] = {}
        self._facts: list[Fact] = []

    # --- entities ---------------------------------------------------------

    def add_entity(self, entity: object) -> bool:
        """Add an entity, idempotent by id. Return True if it was new."""
        kind = entity_kind(entity)
        bucket = self._entities.setdefault(kind, {})
        ident = getattr(entity, "id")
        if ident in bucket:
            return False
        bucket[ident] = entity
        return True

    def add_target(self, target: Target) -> bool:
        return self.add_entity(target)

    def entities(self, kind: str) -> tuple[object, ...]:
        return tuple(self._entities.get(kind, {}).values())

    def targets(self) -> tuple[Target, ...]:
        return self.entities("target")  # type: ignore[return-value]

    def credentials(self) -> tuple[Credential, ...]:
        return self.entities("credential")  # type: ignore[return-value]

    def identities(self) -> tuple[Identity, ...]:
        return self.entities("identity")  # type: ignore[return-value]

    # --- growth -----------------------------------------------------------

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

    # --- serialization for checkpoint and resume -------------------------

    def to_dict(self) -> dict:
        return {
            "entities": [
                entity_to_dict(e)
                for bucket in self._entities.values()
                for e in bucket.values()
            ],
            "facts": [self._fact_to_dict(f) for f in self._facts],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SituationGraph":
        graph = cls()
        for ed in data.get("entities", []):
            graph.add_entity(entity_from_dict(ed))
        for fd in data.get("facts", []):
            graph._facts.append(cls._fact_from_dict(fd))
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

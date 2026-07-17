"""The world model: the blackboard, the single live picture of what is known.

All long-horizon state lives here, never inside a model context, so a run can be
checkpointed and resumed. The model has two records. A `Node` is a thing that
exists, a target, a discovered asset, a minted finding. A `Fact` is a statement
learned about a node, and it may carry new nodes it discovered, which is the only
way the surface grows.

Both records tag themselves with a string, `Node.type` and `Fact.kind`, so the
engine can index and query them generically without knowing any domain. The real
data rides in `payload`, a frozen dataclass the scenario defines, so scenario code
reads typed attributes and never a loosely-typed string map. The engine treats the
payload as opaque, it only ever reads the tag, the id, and the `about` link.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True, kw_only=True)
class Node:
    """A thing that exists in the world, keyed by a unique id and a type tag.

    The payload is the scenario's own frozen dataclass, so a domain carries typed
    data without the engine naming any field. The engine reads only `id` and `type`.
    """

    id: str
    type: str
    payload: Any = None


@dataclass(frozen=True, kw_only=True)
class Fact:
    """A statement learned about one node, optionally carrying new nodes.

    `about` is the id of the node the fact concerns. `kind` tags the fact so rules
    and triage can query for it. `yields` holds nodes the fact discovered, absorbed
    into the world when the fact is recorded, so growth stays explicit and data
    driven rather than hidden in engine code.
    """

    kind: str
    about: str
    payload: Any = None
    yields: tuple[Node, ...] = ()


class World:
    """Nodes keyed by id, plus the facts learned about them.

    The pokeable surface is computed from the current state, not enumerated once at
    the start. Recording a fact can add nodes, and the planner re-derives the next
    tasks from the grown world each round, so the surface grows live.
    """

    def __init__(self) -> None:
        self._nodes: dict[str, Node] = {}
        self._facts: list[Fact] = []

    def add(self, node: Node) -> bool:
        """Add a node, idempotent by id. Return True when it was new.

        Idempotence is load-bearing: a planner may re-derive the same discovery
        every round, and the world absorbs the repeat without duplicating it.
        """
        if node.id in self._nodes:
            return False
        self._nodes[node.id] = node
        return True

    def node(self, node_id: str) -> Node | None:
        return self._nodes.get(node_id)

    def nodes(self, node_type: str | None = None) -> tuple[Node, ...]:
        if node_type is None:
            return tuple(self._nodes.values())
        return tuple(n for n in self._nodes.values() if n.type == node_type)

    def absorb(self, facts: Iterable[Fact]) -> int:
        """Record facts and merge any nodes they yield. Return the new-node count."""
        added = 0
        for fact in facts:
            self._facts.append(fact)
            for node in fact.yields:
                if self.add(node):
                    added += 1
        return added

    def facts(self, kind: str | None = None, about: str | None = None) -> tuple[Fact, ...]:
        return tuple(
            f for f in self._facts
            if (kind is None or f.kind == kind) and (about is None or f.about == about)
        )

    def has_fact(self, about: str, kind: str) -> bool:
        return any(f.about == about and f.kind == kind for f in self._facts)

    def latest(self, kind: str, about: str) -> Fact | None:
        """The most recent fact of a kind about a node, or None. Later facts win."""
        found: Fact | None = None
        for f in self._facts:
            if f.kind == kind and f.about == about:
                found = f
        return found

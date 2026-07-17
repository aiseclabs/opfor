"""Planning: propose the next tasks for a phase, declaratively where possible.

A planner reads the world and proposes tasks. It never runs a tool, that is the
capability's job. The old engine made every scenario hand-write the same loop,
"for each node lacking this fact, emit that task, and once these are all recorded,
emit the next". That boilerplate is now the `each` rule and the `RuleSet` that
groups rules by phase, so a scenario declares the pipeline instead of coding it.

An open-ended phase with no fixed rule uses a `Planner` subclass that calls a model
to propose tasks. The model only proposes, scope still authorizes and triage still
judges, so no judgment leaks into planning.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Callable

from opfor.core.capability import Task
from opfor.core.phase import Phase
from opfor.core.world import World

# A rule reads the world for one phase and returns candidate tasks. The engine
# dedupes and drops any task already run, so a rule re-emitting is harmless.
Rule = Callable[[World], list[Task]]


class Planner(ABC):
    @abstractmethod
    def plan(self, world: World, phase: Phase) -> list[Task]:
        """Propose tasks for the given phase. Never runs tools."""


class RuleSet(Planner):
    """A planner built from rules grouped by phase, the declarative common case."""

    def __init__(self, rules: dict[Phase, list[Rule]]) -> None:
        self._rules = rules

    def plan(self, world: World, phase: Phase) -> list[Task]:
        tasks: list[Task] = []
        for rule in self._rules.get(phase, []):
            tasks.extend(rule(world))
        return tasks


def each(
    node_type: str,
    *,
    run: str,
    unless_fact: str | None = None,
    where: Callable[[object], bool] | None = None,
    scope_target: Callable[[object], str | None] | None = None,
) -> Rule:
    """A rule that runs a capability once per node of a type.

    `unless_fact` skips a node that already carries a fact of that kind, which is how
    a stage waits for its predecessor without a task dependency. `where` filters on the
    node's payload, so a rule can target only some nodes such as the seed roots.
    `scope_target` reads a locator off the payload, so a non-osint capability is authorized
    against the right target.
    """

    def rule(world: World) -> list[Task]:
        tasks: list[Task] = []
        for node in world.nodes(node_type):
            if where is not None and not where(node.payload):
                continue
            if unless_fact is not None and world.has_fact(node.id, unless_fact):
                continue
            tasks.append(Task(
                capability=run,
                node=node.id,
                scope_target=scope_target(node.payload) if scope_target else None,
            ))
        return tasks

    return rule

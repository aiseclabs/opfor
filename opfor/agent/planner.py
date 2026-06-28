"""Planners, the decision layer (PEP "Planner").

A planner reads the situation graph and proposes the next tasks. It never runs a
tool, that is the executor's job. Two kinds:

- DeterministicPlanner / FunctionPlanner: rule based, for known phases like
  recon. Cheap, stable, repeatable. Emit a task only once its preconditions hold
  in the graph, so the pokeable surface grows live as facts arrive.
- (later) ModelPlanner: asks a model for the next tasks in open-ended phases like
  exploitation, where there is no fixed playbook.

A planner may re-emit applicable tasks every round, the TaskGraph dedupes by id.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Callable

from opfor.engine.graph import SituationGraph
from opfor.engine.tasks import Task


class Planner(ABC):
    @abstractmethod
    def expand(self, graph: SituationGraph) -> list[Task]:
        """Propose tasks given the current situation graph. Never runs tools."""


class FunctionPlanner(Planner):
    """Wrap a plain function graph -> list[Task] as a deterministic planner."""

    def __init__(self, rule: Callable[[SituationGraph], list[Task]]) -> None:
        self._rule = rule

    def expand(self, graph: SituationGraph) -> list[Task]:
        return list(self._rule(graph))

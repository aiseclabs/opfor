"""The hand contract, the only verbs the engine knows.

A hand reaches a kind of target and reports raw reactions. It must not read
knowledge and must not make attack decisions. Invariant 1 and invariant 2 in
AGENTS.md live or die here, so keep this file dumb on purpose.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from opfor.model import Entrypoint, Fact, Observation, Target

# Forward reference only, hands receive the graph but should treat it as a
# read-only view of current state, never as a place to make decisions.
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from opfor.engine.graph import SituationGraph
    from opfor.engine.tasks import Task


class Executor(ABC):
    """An executor runs one task with one tool and reports raw, then structures it.

    This is the PEP "Executor + Perceptor": run does the deed and returns the raw
    observation, perceive turns that raw output into facts for the blackboard. An
    executor handles exactly one capability, makes no attack decisions, and never
    reads knowledge. One capability per executor keeps them thin and swappable.
    """

    capability: str

    @abstractmethod
    def run(self, task: "Task", graph: "SituationGraph") -> Observation:
        """Carry out one task and return the raw observation. No judgment."""

    @abstractmethod
    def perceive(self, observation: Observation) -> list[Fact]:
        """Turn a raw observation into structured facts for the situation graph."""


class Hand(ABC):
    """One hand per kind of target. Three verbs, no judgment."""

    name: str

    @abstractmethod
    def enumerate(self, target: Target, graph: "SituationGraph") -> list[Entrypoint]:
        """List the entrypoints currently pokeable on target.

        Re-callable across the run. As the graph gains credentials and
        artifacts, a later call may surface entrypoints the first call could
        not reach. The hand reads the graph only to compute reachability, never
        to decide what to attack.
        """

    @abstractmethod
    def act(self, entrypoint: Entrypoint, action: str, params: dict) -> Observation:
        """Perform one action and return the raw observation.

        Never interpret the result. Return raw bytes, status, and metadata. For
        an action whose result arrives later, return an Observation with pending
        True and a handle the engine can match against a future event.
        """

    @abstractmethod
    def normalize(self, observation: Observation) -> list[Fact]:
        """Turn a raw observation into structured facts for the graph.

        A fact may carry yields, newly discovered entities, which is how the
        pokeable surface grows. Still no judgment of success here.
        """

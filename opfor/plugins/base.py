"""The executor contract, the only verbs the engine knows.

An executor runs one task with one tool and reports raw, then structures it. This
is the PEP "Executor + Perceptor": run does the deed and returns the raw
observation, perceive turns that raw output into facts for the blackboard. An
executor handles exactly one capability, makes no attack decisions, and never
reads knowledge. Invariant 1 and invariant 2 live or die here, so keep this dumb
on purpose.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from opfor.model import Fact, Observation

if TYPE_CHECKING:
    from opfor.engine.graph import SituationGraph
    from opfor.engine.tasks import Task


class Executor(ABC):
    """Runs one task with one tool and reports raw, then structures it."""

    capability: str

    @abstractmethod
    def run(self, task: "Task", graph: "SituationGraph") -> Observation:
        """Carry out one task and return the raw observation. No judgment."""

    @abstractmethod
    def perceive(self, observation: Observation) -> list[Fact]:
        """Turn a raw observation into structured facts for the situation graph."""

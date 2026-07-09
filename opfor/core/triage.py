"""Triage: the judge, the one place that decides what is real and how severe.

Judgment is deliberately separate from planning. A planner proposes moves, a
capability reports raw facts, and triage reads the enriched world and rules
candidates real or false, grading each survivor against the scenario's rubric.
This is invariant 2 given a home: success is judged, never hardcoded in a
capability. Triage runs once, in the TRIAGE phase, and returns the findings a run
reports. It may be rule-based or model-backed, the engine does not care which.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from opfor.core.result import Finding
from opfor.core.world import World


class Triage(ABC):
    @abstractmethod
    def judge(self, world: World) -> list[Finding]:
        """Read the enriched world and return the findings worth reporting.

        Returning an empty list is a real verdict, nothing rose to a finding, not a
        failure. A candidate is dropped only on a controlling fact triage can read,
        never on an assumption, so recall stays the first priority.
        """

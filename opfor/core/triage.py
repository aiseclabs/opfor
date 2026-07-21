"""Triage: the judge, the one place that decides what is real and how severe.

Judgment is deliberately separate from planning. A planner proposes moves, a
capability reports raw facts, and triage reads the enriched world and rules
candidates real or false, grading each survivor against the scenario's rubric.
This is invariant 2 given a home: success is judged, never hardcoded in a
capability. Triage runs once, in the TRIAGE phase, and returns the findings a run
reports. It may be rule-based or model-backed, the engine does not care which.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod

from opfor.core.result import Finding
from opfor.core.world import World

# The judging modes, read from the environment at the call that builds a scenario's triage, not
# frozen at import. This is triage policy, so it lives with the triage layer rather than in the
# provider transport factory. An unknown mode would silently run the standard pass instead of the
# adversarial one the operator asked for, a wrong result with no error, so it fails loud.
TRIAGE_MODES = ("standard", "adversarial")


def triage_mode() -> str:
    """The triage judging mode, `standard` single-model by default or `adversarial`."""
    mode = os.environ.get("OPFOR_TRIAGE_MODE", "standard")
    if mode not in TRIAGE_MODES:
        raise ValueError(
            f"triage mode {mode!r} is not supported, set OPFOR_TRIAGE_MODE to one of "
            f"{', '.join(TRIAGE_MODES)}")
    return mode


def role_model(role: str, base: str) -> str:
    """The model for an adversarial role, its own `OPFOR_<ROLE>_MODEL` or the base model.

    A distinct model in the challenger or judge seat gives an uncorrelated second opinion, the
    point of the adversarial pass. With none set the role reuses the base model, which still gives
    an independent pass, just a correlated one."""
    return os.environ.get(f"OPFOR_{role.upper()}_MODEL") or base


class Triage(ABC):
    @abstractmethod
    def judge(self, world: World) -> list[Finding]:
        """Read the enriched world and return the findings worth reporting.

        Returning an empty list is a real verdict, nothing rose to a finding, not a
        failure. A candidate is dropped only on a controlling fact triage can read,
        never on an assumption, so recall stays the first priority.
        """

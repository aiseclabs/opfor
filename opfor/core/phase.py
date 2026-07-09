"""The lifecycle spine: the fixed, ordered phases every campaign runs through.

The spine is the answer to scenarios that never close the loop. A run does not
stop when it runs out of work, it advances through a fixed sequence of phases and
stops at the terminal phase the scenario declares. Because the sequence is fixed
and the terminal is declared, the engine always knows how far a run got and
whether it finished, so a run that stalls early is a visible failure to close, not
a silently clean result.

Ordering is the only thing the values carry, so an `IntEnum` lets the engine ask
"is this phase at or before the terminal" with a comparison. A scenario is free to
use only some phases. A phase with no work is instantly quiescent and the engine
advances past it.
"""

from __future__ import annotations

from enum import IntEnum


class Phase(IntEnum):
    """One step on the fixed lifecycle spine, ordered from seeding to confirmation.

    SEED plants the campaign's given targets. MAP discovers more nodes, the breadth
    of the surface. ENRICH adds facts to known nodes, the depth. TRIAGE is where the
    judge rules candidates real or false and grades them, the only phase that mints
    findings. EXPLOIT and CONFIRM are the intrusive half, reserved for a scenario
    that acts on a target under authorization, not used by a recon scenario.
    """

    SEED = 0
    MAP = 1
    ENRICH = 2
    TRIAGE = 3
    EXPLOIT = 4
    CONFIRM = 5

    @classmethod
    def upto(cls, terminal: "Phase") -> tuple["Phase", ...]:
        """The phases from SEED through the terminal, in order, inclusive.

        The engine iterates exactly this sequence, so the terminal a scenario
        declares is the contract for how far a run is meant to go.
        """
        return tuple(p for p in cls if p <= terminal)

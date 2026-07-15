"""Post-triage: a step the engine runs once after TRIAGE, before the intrusive half.

Triage judges the enriched world into findings, and that is all it does, invariant 2. Some
scenarios then need a deterministic step that neither judges nor mints, it grounds a finding
in a request the surface actually observed and materializes the world nodes the later phases
act on. That is not a verdict and it is not a capability action, so it lives here as a step
the engine runs after TRIAGE rather than inside triage or a capability.

The step returns one finding per input finding, so it never mints and never drops, and the
surface a run reports is unchanged in count. It may add nodes to the world for a later phase
to act on. A scenario that needs no such step declares none, and the engine runs TRIAGE
straight into the next phase.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from opfor.core.result import Finding
from opfor.core.world import World


class PostTriage(ABC):
    @abstractmethod
    def run(self, world: World, findings: tuple[Finding, ...]) -> list[Finding]:
        """Run once after TRIAGE. Return one finding per input finding, in order, annotated
        or regraded but never minted or dropped. May add nodes to the world for a later phase
        to act on, so world mutation stays out of triage."""

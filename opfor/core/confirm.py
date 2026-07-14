"""Confirm: a second pass over the findings, now with live reproduction receipts.

Triage judges the enriched world into findings. When a scenario runs the intrusive half,
the EXPLOIT phase replays each finding's grounded safe-read request and records the live
receipt onto the world. Confirm is the judgment that reads those receipts back and regrades
each finding on what the request actually returned, not on what triage inferred. A receipt
that returns the expected content confirms a finding, one that returns a generic shell where
raw content was claimed weakens it, and no response leaves it unconfirmed.

This is still judgment, so it lives here beside triage and not in a capability, invariant 2.
Confirm never mints a finding out of nothing, it only regrades the findings triage already
produced, so the surface a run reports is never grown by the confirm pass. A scenario that
never reproduces declares no confirm and the CONFIRM phase does nothing.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from opfor.core.result import Finding
from opfor.core.world import World


class Confirm(ABC):
    @abstractmethod
    def reconfirm(self, world: World, findings: tuple[Finding, ...]) -> list[Finding]:
        """Regrade the findings given the reproduction receipts recorded on the world.

        Return one finding per input finding, in order. A finding with no receipt is
        returned unchanged, a verdict is only drawn where a live request was replayed. A
        regrade never drops a finding, so recall is preserved, a refuted claim is graded
        down and carries the reason rather than silently vanishing.
        """

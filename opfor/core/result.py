"""The result contract: a finding, and the report a run produces.

A `Finding` is the deliverable of a scenario, one judged issue with a location, a
severity, and its evidence. A scenario's triage mints them, so the engine never
decides what is real. A `Report` is the typed answer to the three questions a run
must always answer: did it close, how far did it get, and what did it find. A run
that suspends says so, so incomplete work is never dressed as complete.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from opfor.core.phase import Phase

# A run either ran the whole spine to its terminal, or stopped short and can resume.
CLOSED = "closed"
SUSPENDED = "suspended"


@dataclass(frozen=True, kw_only=True)
class Finding:
    """One judged issue. `where` is a locator such as a node id or an address, and
    `severity` is graded by triage against the scenario's rubric. `data` carries the
    scenario's structured axes so an operator can sort and filter without parsing prose."""

    id: str
    title: str
    severity: str
    where: str
    evidence: str = ""
    # A safe, reproducible read that demonstrates the finding, never an attack, so an
    # operator can confirm it by hand. Empty when the finding needs no command to show.
    poc: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, kw_only=True)
class Report:
    """The outcome of one run, the typed answer to did it close, how far, and what.

    `reached` is the last phase the engine completed, `terminal` is the phase the
    scenario declared as its finish line. A closed run reached its terminal. A
    suspended run did not, and `notes` says why, such as an exhausted budget or work
    awaiting an async result. Coverage caveats also land in `notes`, so a bounded or
    truncated run is loud about it.
    """

    scenario: str
    status: str
    reached: Phase
    terminal: Phase
    findings: tuple[Finding, ...] = ()
    notes: tuple[str, ...] = ()

    @property
    def closed(self) -> bool:
        return self.status == CLOSED and self.reached >= self.terminal

"""The finding: one judged issue, the deliverable of a scenario.

A `Finding` is a leaf data type with no engine dependency, so both the result contract and
the resumable run state can carry findings without either reaching for the other. A scenario's
triage mints them, so the engine never decides what is real.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


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

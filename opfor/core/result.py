"""The result contract: a finding, and the report a run produces.

A `Finding` is the deliverable of a scenario, one judged issue with a location, a
severity, and its evidence. A scenario's triage mints them, so the engine never
decides what is real. A `Report` is the typed answer to the three questions a run
must always answer: did it close, how far did it get, and what did it find. A run
that suspends says so, so incomplete work is never dressed as complete.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any

from opfor.core.phase import Phase

if TYPE_CHECKING:
    from opfor.core.engine import RunState

# A run either ran the whole spine to its terminal, stopped short but can resume, or hit an
# error it cannot resume past. A suspended run is a resumable stall, an exhausted budget or
# parked async work. An errored run is a code-level failure in the planner or a judge, a
# distinct status so an operator or CI never mistakes a deterministic crash for a stall to
# retry.
CLOSED = "closed"
SUSPENDED = "suspended"
ERRORED = "errored"


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
    awaiting an async result. An errored run hit a code-level failure, `notes` names the
    exception. Coverage caveats also land in `notes`, so a bounded or truncated run is loud.

    A suspended run carries the resumable `state` a resume continues from, and names any
    async handles it is waiting on in `pending`. State rides every suspension, a budget one
    included, though a budget suspension only makes progress once the ceiling is raised. A
    closed or errored run carries neither, its state is not resumable.
    """

    scenario: str
    status: str
    reached: Phase
    terminal: Phase
    findings: tuple[Finding, ...] = ()
    notes: tuple[str, ...] = ()
    # The async handles a suspended run is waiting on, the keys to feed results back through.
    pending: tuple[str, ...] = ()
    # The resumable state of a suspended run, live objects rather than a serialized checkpoint,
    # so `engine.resume_async` continues it in process. None on a closed or errored run.
    state: "RunState | None" = None

    @property
    def closed(self) -> bool:
        return self.status == CLOSED and self.reached >= self.terminal

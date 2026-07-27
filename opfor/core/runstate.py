"""RunState: the resumable state of a run, everything the loop needs to resume.

It lives apart from the engine that drives it and the result contract that carries it, so the
result contract can reference it without a back edge to the engine. The engine holds only the
loop, this holds only the state, and `Report` rides one onward when a run suspends.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from opfor.core.budget import Budget
from opfor.core.capability import Task
from opfor.core.finding import Finding
from opfor.core.ledger import Ledger
from opfor.core.phase import Phase
from opfor.core.scenario import Scenario
from opfor.core.scope import Scope
from opfor.core.world import World


@dataclass
class RunState:
    """The resumable state of a run, everything the loop needs to pick up where it stopped.

    A closed run needs none of this again, so the state rides only a suspended report. It
    holds live objects rather than a serialized checkpoint, so resume is in process, the
    async result is fed back through the same handle and the same world it parked against.
    `resume_from` is the phase a suspend stopped in, so the loop skips the phases already
    completed and re-enters the one that still has work.
    """

    scenario: Scenario
    world: World
    scope: Scope
    budget: Budget
    ledger: Ledger
    done: set[str] = field(default_factory=set)         # task ids that reached a terminal outcome
    pending: dict[str, Task] = field(default_factory=dict)  # handle -> task parked for an async result
    findings: tuple[Finding, ...] = ()
    notes: list[str] = field(default_factory=list)
    reached: Phase = Phase.SEED
    resume_from: Phase | None = None
    max_workers: int = 8
    max_retries: int = 2         # extra attempts after the first when a task fails transiently
    task_timeout: float = 600.0  # per-task wall-clock, a generous hang net, not a slow-task cap
    retry_backoff: float = 2.0   # seconds, scaled by attempt number between retries
    checkpoint_path: Path | None = None  # when set, the run saves its state here as it advances

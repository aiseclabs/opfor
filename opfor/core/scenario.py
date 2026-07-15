"""A scenario: the plugin bundle the engine runs, all data and seams, no engine code.

A scenario supplies the capabilities that act, the planner that proposes tasks per
phase, the triage that judges, the terminal phase that declares how far the run
goes, and a content root where its knowledge markdown and data files live. The
engine imports no scenario, the runner resolves one and hands the engine its parts.
Adding a scenario is a new package under `opfor/scenarios/`, never an engine change,
which is how one engine drives web, network, chain, and phishing alike.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from opfor.core.capability import Capability
from opfor.core.confirm import Confirm
from opfor.core.phase import Phase
from opfor.core.post_triage import PostTriage
from opfor.core.rules import Planner
from opfor.core.triage import Triage


@dataclass(frozen=True, kw_only=True)
class Scenario:
    name: str
    content_root: Path
    capabilities: tuple[Capability, ...]
    planner: Planner
    triage: Triage
    # The last phase this scenario runs. A recon scenario stops at TRIAGE, which is a
    # declared finish line, so reaching it is a closed run and stopping short is not.
    terminal: Phase = Phase.TRIAGE
    # A deterministic step the engine runs once after TRIAGE, to ground findings in observed
    # requests and materialize the nodes later phases act on. Absent when a scenario needs
    # none, then TRIAGE runs straight into the next phase. Judgment stays in triage, world
    # mutation stays here, invariant 2.
    post_triage: PostTriage | None = None
    # The confirm judge, run in the CONFIRM phase to regrade findings against the live
    # reproduction receipts. Absent when a scenario never reproduces, then CONFIRM is idle.
    confirm: Confirm | None = None

    @property
    def knowledge_dir(self) -> Path:
        return self.content_root / "knowledge"

    def capability(self, name: str) -> Capability:
        """Resolve a capability by name, fail loud when a task names an unknown one."""
        for cap in self.capabilities:
            if cap.name == name:
                return cap
        known = ", ".join(c.name for c in self.capabilities)
        raise KeyError(f"unknown capability {name!r} in scenario {self.name}, known: {known}")

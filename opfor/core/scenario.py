"""A scenario: the plugin bundle the engine runs, all data and seams, no engine code.

A scenario supplies the capabilities that act, the planner that proposes tasks per
phase, the triage that judges, the terminal phase that declares how far the run
goes, and a content root anchoring the package. Its knowledge lives in asset-class
subtrees, read through the bundle each asset class assembles, not off the root. The
engine imports no scenario, the runner resolves one and hands the engine its parts.
Adding a scenario is a new package under `opfor/scenarios/`, never an engine change,
which is how one engine drives web, network, chain, and phishing alike.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping

from opfor.core.capability import Capability
from opfor.core.confirm import Confirm
from opfor.core.phase import Phase
from opfor.core.grounding import Grounding
from opfor.core.rules import Planner
from opfor.core.scope import ExactScope, ScopeMatcher
from opfor.core.triage import Triage


@dataclass(frozen=True, kw_only=True)
class Scenario:
    name: str
    # The scenario package root, a stable anchor for the run. Knowledge does not live at
    # `content_root / "knowledge"`, a scenario reads it from each asset class bundle's own
    # `knowledge_dir`, so this root names the package, not the knowledge tree.
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
    grounding: Grounding | None = None
    # The confirm judge, run in the CONFIRM phase to regrade findings against the live
    # reproduction receipts. Absent when a scenario never reproduces, then CONFIRM is idle.
    confirm: Confirm | None = None
    # The scenario's payload dataclasses, keyed by class name, so a durable checkpoint can
    # serialize and rebuild the world's typed payloads without the kernel naming one. A
    # scenario that never checkpoints may leave it empty, then only a payload-free world
    # round-trips. Adding a payload type is listing it here, not touching the codec.
    payloads: Mapping[str, type] = field(default_factory=dict)
    # Rebuilds this scenario's scope matcher from the dict a checkpoint stored, so a resumed run
    # re-authorizes by the same in-scope rule. The default rebuilds exact-string membership,
    # which the kernel owns, so a scenario whose targets are opaque ids wires nothing. A
    # scenario with a richer rule, a host suffix say, passes its own factory, and the kernel
    # stays free of naming a host.
    scope_matcher: Callable[[Mapping], ScopeMatcher] = ExactScope.from_dict

    def capability(self, name: str) -> Capability:
        """Resolve a capability by name, fail loud when a task names an unknown one."""
        for cap in self.capabilities:
            if cap.name == name:
                return cap
        known = ", ".join(c.name for c in self.capabilities)
        raise KeyError(f"unknown capability {name!r} in scenario {self.name}, known: {known}")

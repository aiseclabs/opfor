"""The asset-class plugin contract: the bundle a class contributes and the gate that enables it.

An asset class is to a scenario what a scenario is to the engine, a self-contained plugin. It owns
its node and fact payloads, its capabilities, its planner rules, and its own knowledge, and it names
no other class. Each class exposes `assemble`, which takes the injected seams a run wires and a test
fakes, and returns a `ClassBundle`, the capabilities and rules the class contributes plus the
knowledge directory its triage reads, if any. The scenario concatenates the bundles, so the classes
compose without knowing each other.

The domain class is the only one the scenario ships today. The `ClassBundle` seam and the
`class_enabled` gate are the plugin contract, but the scenario's `build` still wires the domain
class's own seams by name, so adding a second class means extending that wiring, not a one-line
edit. When a second class arrives, lift the seam wiring behind a registry. Until then this is
honest scaffolding for one class, not a proven multi-class abstraction.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from opfor.core import Capability


@dataclass(frozen=True, kw_only=True)
class ClassBundle:
    """One asset class's contribution to a scenario. `map_rules` and `enrich_rules` are the
    rules the class adds to those phases, `knowledge_dir` is where its triage knowledge
    lives, or None when the class mints only structural findings and reads no knowledge, and
    `reproductions` are the read-only CVE reproduction recipes its knowledge carries, which the
    scenario grounder reads to reproduce a known vulnerability."""

    name: str
    capabilities: tuple[Capability, ...]
    map_rules: tuple = ()
    enrich_rules: tuple = ()
    knowledge_dir: Path | None = None
    reproductions: tuple = ()


def class_enabled(org, name: str) -> bool:
    """Whether an asset class runs, given the org's optional class restriction. Empty means
    all classes run, so a bare seed maps every class."""
    return not org.classes or name in org.classes

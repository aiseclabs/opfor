"""Asset classes, the plugins a scenario is built from, one per kind of asset.

An asset class is to a scenario what a scenario is to the engine, a self-contained
plugin. It owns its node and fact payloads, its capabilities, its planner rules, and its
own knowledge, and it names no other class. The domain class, the one the scenario ships
today, knows nothing of any other, and adding a class is a new package here plus one line
in the scenario's `build`, never an edit to an existing class.

Each class exposes `assemble`, which takes the injected seams a run wires and a test
fakes, and returns a `ClassBundle`, the capabilities and rules the class contributes plus
the knowledge directory its triage reads, if any. The scenario concatenates the bundles.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from opfor.core import Capability


@dataclass(frozen=True, kw_only=True)
class ClassBundle:
    """One asset class's contribution to a scenario. `map_rules` and `enrich_rules` are the
    rules the class adds to those phases, `knowledge_dir` is where its triage knowledge
    lives, or None when the class mints only structural findings and reads no knowledge."""

    name: str
    capabilities: tuple[Capability, ...]
    map_rules: tuple = ()
    enrich_rules: tuple = ()
    knowledge_dir: Path | None = None


def class_enabled(org, name: str) -> bool:
    """Whether an asset class runs, given the org's optional class restriction. Empty means
    all classes run, so a bare seed maps every class."""
    return not org.classes or name in org.classes

"""The asset-class plugin contract: the bundle a class contributes to a scenario.

An asset class is to a scenario what a scenario is to the engine, a self-contained plugin. It owns
its node and fact payloads, its capabilities, its planner rules, and its own knowledge, and it names
no other class. Each class exposes `assemble`, which takes the injected seams a run wires and a test
fakes, and returns a `ClassBundle`, the capabilities and rules the class contributes plus the
knowledge directory its triage reads, if any. The scenario concatenates the bundles, so the classes
compose without knowing each other.

The scenario ships two classes, `domain` and `chain`, each a self-contained package under
`assets/` exposing its own `build`, `prepare_run`, `report_view`, and `seed`. The scenario shell
dispatches a run to exactly one of them by the seed the request fills, so the classes never share
a pipeline. `ClassBundle` is the shape each class's `assemble` returns, the capabilities and rules
it contributes plus its knowledge directory. A third class is a new package plus a branch in the
shell dispatcher, the kernel does not change.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from opfor.core import Capability, Rule


@dataclass(frozen=True, kw_only=True)
class ClassBundle:
    """One asset class's contribution to a scenario. `map_rules` and `enrich_rules` are the
    rules the class adds to those phases, and `knowledge_dir` is where its triage knowledge
    lives, or None when the class mints only structural findings and reads no knowledge."""

    capabilities: tuple[Capability, ...]
    map_rules: tuple[Rule, ...] = ()
    enrich_rules: tuple[Rule, ...] = ()
    knowledge_dir: Path | None = None

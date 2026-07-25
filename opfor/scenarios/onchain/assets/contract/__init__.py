"""The contract asset class: a chain's active DEX surface to a ranked audit queue.

It owns the sweep-and-pivot discovery, the source, identify, funds, interface, and signal
enrichment, and the detection data its interface and signal scans apply, all under its
`knowledge` tree. It declares that knowledge directory for the report and the model-backed triage
to read. The seams are injected, so a test drives the class with fixtures.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from opfor.scenarios.onchain.assets.contract import planner
from opfor.scenarios.onchain.assets.contract.capabilities import (
    EnumInterfaces,
    FetchSource,
    FingerprintSource,
    IdentifyContract,
    PivotRelated,
    ReadFunds,
    ResolveProxy,
    ScanSignals,
    SweepPools,
)
from opfor.scenarios.onchain.assets.contract.signals import load_detections

KNOWLEDGE = Path(__file__).resolve().parent / "knowledge"
DETECTIONS = KNOWLEDGE / "detections" / "contract-signals"


@dataclass(frozen=True, kw_only=True)
class ClassBundle:
    """One asset class's contribution to the scenario, its capabilities, its per-phase rules, and
    the knowledge directory its triage reads. The scenario concatenates one bundle per class, so a
    class is added or swapped without touching the scenario loop."""

    name: str
    capabilities: tuple
    map_rules: tuple
    enrich_rules: tuple
    knowledge_dir: Path


def assemble(*, sweep_fn, pivot_fn, source_fn, identify_fn, funds_fn, resolve_fn) -> ClassBundle:
    """The contract class's contribution. The seams are the public sources, injected so a test
    drives the class with fixtures. The detection data is loaded once here at assemble time, not
    at import, so the content root stays swappable and importing the class triggers no file IO."""
    detections = load_detections(DETECTIONS)
    capabilities = (
        SweepPools(sweep_fn),
        PivotRelated(pivot_fn),
        FetchSource(source_fn),
        IdentifyContract(identify_fn),
        ResolveProxy(resolve_fn),
        ReadFunds(funds_fn),
        EnumInterfaces(detections),
        ScanSignals(detections),
        FingerprintSource(),
    )
    return ClassBundle(
        name=planner.CLASS,
        capabilities=capabilities,
        map_rules=tuple(planner.map_rules()),
        enrich_rules=tuple(planner.enrich_rules()),
        knowledge_dir=KNOWLEDGE,
    )

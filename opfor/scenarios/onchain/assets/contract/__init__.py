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
from opfor.scenarios.onchain.assets.contract.chains import load_chain_policy, load_vendored_markers
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
class ContractClassBundle:
    """The contract class's contribution to the scenario, its capabilities, its per-phase rules,
    and the knowledge directory its triage reads. This is the contract-specific bundle, distinct
    from attacksurface's `ClassBundle`, which additionally carries CVE reproduction recipes the
    contract scenario has no analogue for. The scenario concatenates one bundle per class, so a
    class is added or swapped without touching the scenario loop."""

    name: str
    capabilities: tuple
    map_rules: tuple
    enrich_rules: tuple
    knowledge_dir: Path


def assemble(*, sweep_fn, pivot_fn, source_fn, identify_fn, funds_fn, resolve_fn) -> ContractClassBundle:
    """The contract class's contribution. The seams are the public sources, injected so a test
    drives the class with fixtures. The detection data, the chain policy, and the vendored-library
    markers are loaded once here at assemble time, not at import, so the content root stays swappable
    and importing the class triggers no file IO. A capability that shapes the surface is handed its
    reference data, it never reaches the knowledge tree itself, invariant 1."""
    detections = load_detections(DETECTIONS)
    policy = load_chain_policy(KNOWLEDGE)
    markers = load_vendored_markers(KNOWLEDGE)
    capabilities = (
        SweepPools(sweep_fn, policy),
        PivotRelated(pivot_fn),
        FetchSource(source_fn),
        IdentifyContract(identify_fn),
        ResolveProxy(resolve_fn),
        ReadFunds(funds_fn),
        EnumInterfaces(detections),
        ScanSignals(detections),
        FingerprintSource(markers),
    )
    return ContractClassBundle(
        name=planner.CLASS,
        capabilities=capabilities,
        map_rules=tuple(planner.map_rules()),
        enrich_rules=tuple(planner.enrich_rules()),
        knowledge_dir=KNOWLEDGE,
    )

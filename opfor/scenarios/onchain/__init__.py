"""The onchain scenario: from a chain's active DEX surface to a ranked audit queue.

The seed is a `Survey`, a chain and the activity floor that bounds the sweep. MAP sweeps the
active DEX pools and pivots from each token or pool to the fund-management contracts behind it,
ENRICH fetches verified source, identifies the role, reads the funds, enumerates the exposed
interfaces, and matches the risk signals, and TRIAGE judges which contracts are worth a manual
audit and how urgently. The terminal is TRIAGE, declared, so a full run is a closed run.

There is no EXPLOIT or CONFIRM phase and no intrusive tier. On-chain there is nothing to reproduce
without sending a transaction, and sending one is out of scope, so the scenario reads public data
and analyzes it statically, more passive than an HTTP probe. Every source is an injected seam, so
a test drives the whole scenario with fixtures. `build` wires the real seams.
"""

from __future__ import annotations

from pathlib import Path

from opfor.core import Node, Phase, RuleSet, Scenario, World
from opfor.scenarios.onchain.assets.contract import assemble
from opfor.scenarios.onchain.assets.contract import identify as contract_identify
from opfor.scenarios.onchain.assets.contract import sources as contract_src
from opfor.scenarios.onchain.assets.contract.known import load_known_infrastructure
from opfor.scenarios.onchain.assets.contract.types import ContractData
from opfor.scenarios.onchain.lifecycle.triage import AuditTriage
from opfor.scenarios.onchain.report import report_view
from opfor.scenarios.onchain.seed import Survey

NAME = "onchain"


def _payloads() -> dict[str, type]:
    """The scenario's payload dataclasses keyed by class name, collected by introspection so a new
    payload type is registered by defining it, not by editing a hand list."""
    from dataclasses import is_dataclass
    from opfor.scenarios.onchain import seed as onchain_seed
    from opfor.scenarios.onchain.assets.contract import types as contract_types

    registry: dict[str, type] = {}
    for module in (onchain_seed, contract_types):
        for name, obj in vars(module).items():
            if isinstance(obj, type) and is_dataclass(obj):
                registry[name] = obj
    return registry


def build(
    *,
    sweep_fn=contract_src.sweep,
    pivot_fn=contract_src.pivot,
    source_fn=contract_src.fetch_source,
    identify_fn=contract_identify.identify_role,
    funds_fn=contract_src.read_funds,
) -> Scenario:
    """Assemble the scenario from the contract class. The seams are injected so a test swaps its
    own. Triage is rule-based, a deterministic audit-worthiness ladder, a model-backed pass over
    the knowledge tree is the tracked next increment."""
    bundle = assemble(sweep_fn=sweep_fn, pivot_fn=pivot_fn, source_fn=source_fn,
                      identify_fn=identify_fn, funds_fn=funds_fn)
    rules = {Phase.MAP: list(bundle.map_rules), Phase.ENRICH: list(bundle.enrich_rules)}
    known = load_known_infrastructure(bundle.knowledge_dir)
    return Scenario(
        name=NAME,
        content_root=Path(__file__).resolve().parent,
        capabilities=bundle.capabilities,
        planner=RuleSet(rules),
        triage=AuditTriage(known_infrastructure=known),
        terminal=Phase.TRIAGE,
        payloads=_payloads(),
    )


def seed(name: str, *, chain="ethereum", min_liquidity=10_000.0, min_volume=5_000.0,
         age_days=90.0, anchors=()) -> World:
    """Build the seed world for a run, a `Survey` node carrying the chain and the sweep floor. When
    anchors are given they enter the world as contract nodes directly, so the enrich pipeline audits
    exactly those contracts, and the planner skips the sweep."""
    anchors = tuple(dict.fromkeys(a.strip().lower() for a in anchors if a.strip()))
    world = World()
    world.add(Node(id=f"survey:{chain}", type="survey",
                   payload=Survey(name=name, chain=chain, min_liquidity=min_liquidity,
                                  min_volume=min_volume, age_days=age_days, anchors=anchors)))
    for address in anchors:
        world.add(Node(id=f"contract:{chain}:{address}", type="contract",
                       payload=ContractData(chain=chain, address=address, role="unknown",
                                            source="anchor")))
    return world


def prepare_run(*, name="", roots=(), roots_file="", hosts=(), hosts_file="",
                tier="recon", authorized=False, reproduce=False, confirm=False):
    """Adapt a CLI run request into this scenario's seeded world, scope, and built scenario. The
    first `--root` names the chain, defaulting to ethereum, so `opfor run onchain` sweeps ethereum
    out of the box. Each `--host` names a contract address to audit directly, a focused run that
    skips the sweep. The scenario is recon-only, so the reproduce and confirm flags do not raise the
    terminal, it always stops at TRIAGE. Reading public chain data is passive, so every capability
    is osint and the recon-tier scope authorizes the run with no per-target list."""
    from opfor.core import Scope

    chain = (roots[0] if roots else "ethereum").strip().lower()
    target = name or f"{chain}-onchain"
    world = seed(target, chain=chain, anchors=tuple(hosts))
    scope = Scope(max_tier="recon")
    return target, world, scope, build()

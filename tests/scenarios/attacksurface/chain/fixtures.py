"""Shared fixtures for the chain asset class tests, the injected seams and the end-to-end runner.

These drive the scenario with deterministic seams, no network, so a run grows pool and token nodes,
pivots to the fund contract behind a token, enriches it, and hands it to triage. The split test
modules import these through a star import, so the fixture set lives in one place rather than being
copied per module.
"""

from __future__ import annotations

import json

from opfor.core import Budget, MockProvider, Scope
from opfor.core.engine import run as engine_run
from opfor.core.phase import Phase
from opfor.scenarios.attacksurface.assets import chain as onchain
from opfor.scenarios.attacksurface.assets.chain import KNOWLEDGE
from opfor.scenarios.attacksurface.assets.chain.identify import Evidence, identify_role
from opfor.scenarios.attacksurface.assets.chain.signals import (
    guarded_functions,
    load_detections,
    scan_source,
)
from opfor.scenarios.attacksurface.assets.chain import DETECTIONS
from opfor.scenarios.attacksurface.assets.chain.sources.observations import (
    FundObservation,
    PoolObservation,
    RelatedObservation,
    SourceObservation,
)

_POOL = "0x1111111111111111111111111111111111111111"
_TOKEN = "0x2222222222222222222222222222222222222222"
_WBNB = "0x3333333333333333333333333333333333333333"
_VAULT = "0x4444444444444444444444444444444444444444"

_VAULT_SOURCE = """
contract Vault {
  function deposit(uint256 amount) external { }
  function withdraw(uint256 shares) external { uint256 a = totalAssets(); }
  function redeem(uint256 shares) external returns (uint256) { }
  function harvest() external { uint112 r = getReserves(); }
  function totalAssets() public view returns (uint256) { }
  function pause() external onlyOwner { }
}
"""


def _fake_sweep(survey):
    return (PoolObservation(address=_POOL, chain=survey.chain, dex_id="pancakeswap",
                            url="https://x/pool", base_address=_TOKEN, base_symbol="FARM",
                            quote_address=_WBNB, quote_symbol="WBNB",
                            liquidity_usd=73_500.0, volume_24h=18_400.0),)


def _fake_pivot(contract):
    if contract.role == "token" and contract.address == _TOKEN:
        return (RelatedObservation(address=_VAULT, chain=contract.chain, role_hint="unknown",
                                   via="holder analysis"),)
    return ()


def _fake_source(contract):
    if contract.address == _VAULT:
        return SourceObservation(verified=True,
                                 functions=("deposit", "withdraw", "redeem", "harvest", "pause"),
                                 source_text=_VAULT_SOURCE)
    if contract.address == _POOL:
        return SourceObservation(verified=True, functions=("swap", "mint", "burn"),
                                 source_text="function swap() external { getReserves(); }")
    return SourceObservation(verified=True, functions=("transfer", "approve"),
                             source_text="contract Token { }")


def _fake_funds(contract, hint_usd):
    if hint_usd and hint_usd > 0:
        return FundObservation(funds_at_risk_usd=hint_usd, assets=("dex_liquidity",))
    if contract.address == _VAULT:
        return FundObservation(funds_at_risk_usd=42_000.0, assets=("stablecoin", "lp"))
    return FundObservation(funds_at_risk_usd=0.0)


def _fake_identify(evidence):
    """A stand-in for the model-backed identify seam, so the pipeline tests stay deterministic and
    the only model call in a run is triage's. It names the vault from its markers and otherwise
    keeps the DEX-layer role hint the sweep or pivot recorded."""
    fns = {f.lower() for f in evidence.functions}
    if {"deposit", "withdraw"} <= fns or "redeem" in fns:
        return "vault"
    return evidence.role_hint


def _reply(*findings):
    """A triage model reply carrying the given findings, the JSON the mock provider returns."""
    return json.dumps({"findings": list(findings)})


# The one contract the fixture run surfaces to triage, the pivoted vault. Its structured facts come
# from the world, so the reply only needs to name the address, the category, and the verdict.
_VAULT_VERDICT = {"address": _VAULT, "category": "external-fund-path", "priority": "A",
                  "severity": "HIGH", "title": "vault worth a full audit",
                  "evidence": "holds funds behind an unguarded deposit and withdraw"}


def _run(triage_responses=None):
    provider = MockProvider(responses=triage_responses if triage_responses is not None
                            else [_reply(_VAULT_VERDICT)])
    scenario = onchain.build(sweep_fn=_fake_sweep, pivot_fn=_fake_pivot, source_fn=_fake_source,
                             identify_fn=_fake_identify, funds_fn=_fake_funds,
                             resolve_fn=lambda addr, chain: "", provider=provider)
    world = onchain.seed("bsc-test", chain="bsc")
    report = engine_run(scenario, world, scope=Scope(max_tier="recon"), budget=Budget(500))
    return report, world


__all__ = [
    "Budget", "MockProvider", "Scope", "engine_run", "Phase", "onchain", "KNOWLEDGE",
    "Evidence", "identify_role", "guarded_functions", "load_detections", "scan_source",
    "DETECTIONS", "FundObservation", "PoolObservation", "RelatedObservation", "SourceObservation",
    "_POOL", "_TOKEN", "_WBNB", "_VAULT", "_VAULT_SOURCE",
    "_fake_sweep", "_fake_pivot", "_fake_source", "_fake_funds", "_fake_identify",
    "_reply", "_VAULT_VERDICT", "_run",
]

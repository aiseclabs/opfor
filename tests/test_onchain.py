"""The onchain scenario, driven end to end with injected fixture seams, no network.

These lock the pipeline the scenario serves: a DEX sweep grows pool and token nodes, a pivot
finds the fund contract behind a token, enrichment identifies it and reads its funds, interfaces,
and signals, and triage mints one audit candidate for the fund contract while the bare pool and
token are not audit targets. They also lock the invariant points: judgment is triage's, a bare
pair is downgraded, and the report is contract-centric.
"""

from __future__ import annotations

import json

import pytest

from opfor.core import Budget, MockProvider, Scope
from opfor.core.engine import run as engine_run
from opfor.core.phase import Phase
from opfor.scenarios import onchain
from opfor.scenarios.onchain.assets.contract import KNOWLEDGE
from opfor.scenarios.onchain.assets.contract.identify import Evidence, identify_role
from opfor.scenarios.onchain.assets.contract.signals import (
    guarded_functions,
    load_detections,
    scan_source,
)
from opfor.scenarios.onchain.assets.contract import DETECTIONS
from opfor.scenarios.onchain.assets.contract.sources.observations import (
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
                             identify_fn=_fake_identify, funds_fn=_fake_funds, provider=provider)
    world = onchain.seed("bsc-test", chain="bsc")
    report = engine_run(scenario, world, scope=Scope(max_tier="recon"), budget=Budget(500))
    return report, world


def test_the_run_closes_at_triage():
    report, _ = _run()
    assert report.closed
    assert report.reached >= Phase.TRIAGE
    assert report.terminal == Phase.TRIAGE


def test_the_pivot_finds_the_fund_contract_behind_a_token():
    _, world = _run()
    ids = {node.id for node in world.nodes("contract")}
    assert f"contract:bsc:{_VAULT}" in ids  # discovered only by pivoting the token, not the sweep
    vault = world.node(f"contract:bsc:{_VAULT}")
    assert vault.payload.source == "pivoted" and vault.payload.related_to == _TOKEN


def test_triage_mints_one_audit_candidate_on_the_fund_contract():
    report, _ = _run()
    assert len(report.findings) == 1  # the vault, not the bare pool or token
    finding = report.findings[0]
    assert finding.severity == "HIGH"  # the model's verdict
    assert finding.where == _VAULT
    data = finding.data
    # the category and priority are the model's judgment
    assert data["kind"] == "external-fund-path" and data["priority"] == "A"
    # the structured facts come from the world, so the record stays faithful to what the run saw
    assert data["role"] == "vault"
    assert "deposit" in data["open_fund_paths"]
    assert {"share_accounting", "dex_spot_price_dependency"} <= set(data["risk_flags"])
    # centralization is recorded but is not what raised the finding
    assert "owner_can_pause" in data["centralization_flags"]


def test_a_bare_pool_is_not_an_audit_target_but_stays_in_the_inventory():
    report, world = _run()
    finding_targets = {f.where for f in report.findings}
    assert _POOL not in finding_targets  # a standard AMM pair is not itself worth auditing
    contracts = {c["address"]: c for c in onchain.report_view(world, report.findings)["contracts"]}
    assert _POOL in contracts  # but it is listed as the surface it was pivoted from
    assert contracts[_POOL]["funds_at_risk_usd"] == 73_500.0
    assert "findings" not in contracts[_POOL]


def test_a_dead_token_with_no_funds_or_signals_is_not_listed():
    report, world = _run()
    contracts = {c["address"] for c in onchain.report_view(world, report.findings)["contracts"]}
    assert _WBNB not in contracts  # no funds, no fund paths, no signals, so nothing to report


def test_the_cli_report_merges_the_contracts_section():
    from opfor.cli import _report_json

    report, world = _run()
    out = _report_json(report, world)
    assert list(out).index("contracts") < list(out).index("findings")
    assert out["contracts"][0]["address"] == _VAULT  # the finding-bearing contract sorts first
    assert json.loads(json.dumps(out))["contracts"][0]["role"] == "vault"  # round-trips as json


def test_onchain_is_registered_and_runnable():
    from opfor.scenarios.registry import known_scenarios, report_adapter, run_adapter

    assert "onchain" in known_scenarios()
    assert run_adapter("onchain") is onchain.prepare_run
    assert report_adapter("onchain") is onchain.report_view


def test_prepare_run_defaults_to_ethereum_and_recon_only():
    target, world, scope, scenario = onchain.prepare_run()
    assert scope.max_tier == "recon"
    assert scenario.terminal == Phase.TRIAGE
    survey = world.node("survey:ethereum")
    assert survey is not None and survey.payload.chain == "ethereum"


def test_identify_is_model_backed_and_fails_loud_on_no_json():
    # identify names the role the model returns for the evidence
    provider = MockProvider(responses=['{"role": "vault"}'])
    assert identify_role(provider, "m", Evidence(functions=("deposit", "withdraw"),
                                                 source_text="contract V {}")) == "vault"
    # a reply carrying no JSON object is a model failure, not a clean unknown, invariant 5
    with pytest.raises(RuntimeError):
        identify_role(MockProvider(responses=["I could not tell"]), "m", Evidence())


def test_an_anchor_run_audits_the_given_contract_and_skips_the_sweep():
    # a focused run: the operator names a contract to audit, no chain sweep
    provider = MockProvider(responses=[_reply(_VAULT_VERDICT)])
    scenario = onchain.build(sweep_fn=_fake_sweep, pivot_fn=_fake_pivot, source_fn=_fake_source,
                             identify_fn=_fake_identify, funds_fn=_fake_funds, provider=provider)
    world = onchain.seed("focus", chain="bsc", anchors=[_VAULT])
    report = engine_run(scenario, world, scope=Scope(max_tier="recon"), budget=Budget(500))

    assert report.closed
    ids = {node.id for node in world.nodes("contract")}
    assert f"contract:bsc:{_VAULT}" in ids  # the anchor was audited
    assert f"contract:bsc:{_POOL}" not in ids  # the sweep did not run, so no pool nodes
    assert len(report.findings) == 1 and report.findings[0].where == _VAULT


def test_compute_funds_prices_native_and_value_tokens():
    from opfor.scenarios.onchain.assets.contract.sources.funds import compute_funds
    from opfor.scenarios.onchain.assets.contract.types import ContractData

    weth, usdt, wbtc = "0xWETH", "0xUSDT", "0xWBTC"
    # native and WETH 18 decimals, USDT 6, WBTC 8, so each token divides by its own decimals
    value_tokens = ((weth, "WETH", "native", 18), (usdt, "USDT", "stable", 6), (wbtc, "WBTC", "priced", 8))
    balances = {usdt.lower(): 1_000 * 10 ** 6, wbtc.lower(): 2 * 10 ** 8}  # holds 1000 USDT, 2 WBTC
    prices = {weth.lower(): 3_000.0, wbtc.lower(): 60_000.0}  # ETH $3000, WBTC $60000

    total, assets = compute_funds(
        ContractData(chain="ethereum", address="0xvault", role="unknown"),
        native_wei_fn=lambda addr, chain: 10 ** 18,  # 1 native coin
        token_balance_fn=lambda token, holder, chain: balances.get(token.lower(), 0),
        price_fn=lambda addr, chain: prices.get(addr.lower()),
        value_tokens=value_tokens)

    assert total == 3_000.0 + 1_000.0 + 120_000.0  # 1 ETH*3000 + 1000 USDT*1 + 2 WBTC*60000
    assert set(assets) == {"native", "USDT", "WBTC"}  # WETH balance was zero, so not counted


def test_triage_drops_known_infrastructure_however_much_it_holds():
    from opfor.core import Fact, Node, World
    from opfor.scenarios.onchain.lifecycle.triage import AuditTriage
    from opfor.scenarios.onchain.assets.contract.types import (
        ContractData, FundFact, IdentityFact, InterfaceFact, InterfaceFn, SignalFact, SourceFact,
    )

    infra = "0x000000000004444c5dc75cb358380d2e3de08a90"  # a router-like singleton, not a target

    def _world(address: str) -> World:
        world = World()
        nid = f"contract:ethereum:{address}"
        world.add(Node(id=nid, type="contract",
                       payload=ContractData(chain="ethereum", address=address, role="unknown")))
        world.absorb([
            Fact(kind="sourced", about=nid, payload=SourceFact(verified=True, source_text="x")),
            Fact(kind="identified", about=nid, payload=IdentityFact(role="router")),
            Fact(kind="funded", about=nid, payload=FundFact(funds_at_risk_usd=200_000_000)),
            Fact(kind="interfaces", about=nid, payload=InterfaceFact(
                functions=(InterfaceFn(name="swap", is_fund_path=True, guarded=False),))),
            Fact(kind="signals", about=nid, payload=SignalFact(
                flags=("dex_spot_price_dependency", "delegatecall"))),
        ])
        return world

    known = {"ethereum": frozenset({infra})}
    # the denylisted contract is pruned before the model, so triage never even calls it
    dropped = AuditTriage(KNOWLEDGE, provider=MockProvider(), model="m",
                          known_infrastructure=known).judge(_world(infra))
    assert dropped == []  # dropped as infra
    # the same shape at a non-denylisted address reaches the model and it judges it high
    other_addr = "0xffff000000000000000000000000000000000001"
    provider = MockProvider(responses=[_reply({"address": other_addr, "category": "external-fund-path",
                                               "priority": "A", "severity": "HIGH", "title": "t",
                                               "evidence": "e"})])
    other = AuditTriage(KNOWLEDGE, provider=provider, model="m",
                        known_infrastructure=known).judge(_world(other_addr))
    assert len(other) == 1 and other[0].severity == "HIGH"


def test_discovery_keeps_only_the_age_band_and_liquidity_floor():
    from opfor.scenarios.onchain.assets.contract.sources.geckoterminal import select
    from opfor.scenarios.onchain.assets.contract.sources.observations import PoolObservation
    from opfor.scenarios.onchain.seed import Survey

    survey = Survey(name="t", chain="ethereum", min_liquidity=50_000,
                    min_age_days=2.0, max_age_days=45.0)
    pools = [
        PoolObservation(address="0x1", chain="ethereum", liquidity_usd=100_000, age_days=10),  # keep
        PoolObservation(address="0x2", chain="ethereum", liquidity_usd=100_000, age_days=0.5),  # too fresh
        PoolObservation(address="0x3", chain="ethereum", liquidity_usd=100_000, age_days=400),  # bluechip age
        PoolObservation(address="0x4", chain="ethereum", liquidity_usd=1_000, age_days=10),  # below floor
        PoolObservation(address="0x5", chain="ethereum", liquidity_usd=100_000, age_days=None),  # age unknown
    ]
    assert {p.address for p in select(pools, survey)} == {"0x1"}


def test_triage_surfaces_an_unverified_high_value_contract():
    from opfor.core import Fact, Node, World
    from opfor.scenarios.onchain.lifecycle.triage import AuditTriage
    from opfor.scenarios.onchain.assets.contract.types import (
        ContractData, FundFact, IdentityFact, SourceFact,
    )

    def _world(funds: float) -> World:
        world = World()
        nid = "contract:ethereum:0xopaque"
        world.add(Node(id=nid, type="contract",
                       payload=ContractData(chain="ethereum", address="0xopaque", role="unknown",
                                            source="pivoted", related_to="0xtoken")))
        world.absorb([Fact(kind="sourced", about=nid, payload=SourceFact(verified=False, note="unverified")),
                      Fact(kind="identified", about=nid, payload=IdentityFact(role="unknown")),
                      Fact(kind="funded", about=nid, payload=FundFact(funds_at_risk_usd=funds))])
        return world

    # unverified but $5M: the model surfaces it on the unverified-high-value class
    big = MockProvider(responses=[_reply({"address": "0xopaque", "category": "unverified-high-value",
                                          "priority": "U", "severity": "MEDIUM",
                                          "title": "opaque high-value", "evidence": "$5M unverified"})])
    findings = AuditTriage(KNOWLEDGE, provider=big, model="m").judge(_world(5_000_000))
    assert len(findings) == 1
    assert findings[0].data["kind"] == "unverified-high-value" and findings[0].severity == "MEDIUM"
    # a small unverified balance the model judges not worth an engineer's time, an empty result
    small = MockProvider(responses=[_reply()])
    assert AuditTriage(KNOWLEDGE, provider=small, model="m").judge(_world(5_000)) == []


def test_funds_prices_the_pivoted_project_token_not_just_the_value_set():
    from opfor.scenarios.onchain.assets.contract.sources.funds import value_tokens_for
    from opfor.scenarios.onchain.assets.contract.types import ContractData

    # a vault pivoted from a project token: its funds live in that token, not in the stable set
    vault = ContractData(chain="ethereum", address="0xvault", role="vault",
                         related_to="0xPROJECT", base_symbol="PRJ")
    tokens = value_tokens_for(vault, decimals_fn=lambda addr, chain: 9)
    assert ("0xPROJECT", "PRJ", "priced", 9) in tokens  # project token priced with its live decimals

    # a contract with no pivot origin gets only the chain's base value set
    bare = ContractData(chain="ethereum", address="0xbare", role="vault")
    assert all(entry[0] != "0xPROJECT" for entry in value_tokens_for(bare, decimals_fn=lambda a, c: 18))


def test_deep_pivot_keeps_frequent_contract_counterparties_only():
    from opfor.scenarios.onchain.assets.contract.sources.pivot import counterparty_pivot
    from opfor.scenarios.onchain.assets.contract.types import ContractData

    staking = "0xaaaa000000000000000000000000000000000001"
    eoa = "0xbbbb000000000000000000000000000000000002"
    dead = "0x000000000000000000000000000000000000dead"
    token = ContractData(chain="bsc", address=_TOKEN, role="token")
    transfers = (
        [{"from": eoa, "to": staking}] * 5      # staking receives the token often, a custody contract
        + [{"from": staking, "to": eoa}] * 2
        + [{"from": eoa, "to": dead}] * 3        # burns, a sink that is never a target
        + [{"from": _TOKEN, "to": eoa}]          # the token itself, excluded
    )
    contracts = {staking}  # the staking address holds code, the eoa does not

    related = counterparty_pivot(
        token, fetch_transfers=lambda addr, chain: transfers,
        is_contract=lambda addr, chain: addr in contracts)

    addresses = {r.address for r in related}
    assert addresses == {staking}  # eoa dropped as not a contract, dead and token excluded
    assert related[0].role_hint == "unknown" and related[0].via == "transfer counterparty"


def test_deep_pivot_caps_breadth():
    from opfor.scenarios.onchain.assets.contract.sources.pivot import counterparty_pivot
    from opfor.scenarios.onchain.assets.contract.types import ContractData

    many = [f"0x{i:040x}" for i in range(1, 30)]
    transfers = [{"from": _TOKEN, "to": addr} for addr in many]
    related = counterparty_pivot(
        ContractData(chain="bsc", address=_TOKEN, role="token"),
        fetch_transfers=lambda a, c: transfers, is_contract=lambda a, c: True, max_deep=8)
    assert len(related) == 8  # bounded so a single hop does not flood MAP


def test_pivot_only_pivots_tokens():
    from opfor.scenarios.onchain.assets.contract.sources.pivot import counterparty_pivot
    from opfor.scenarios.onchain.assets.contract.types import ContractData

    # a pool is the leaf a token pointed at, it is not itself pivoted
    pool = ContractData(chain="bsc", address=_POOL, role="pool")
    related = counterparty_pivot(pool, fetch_transfers=lambda a, c: [], is_contract=lambda a, c: True)
    assert related == []


def test_sweep_skips_the_null_and_burn_sinks():
    # a pool that lists the zero address as a side must not become a contract node, else its
    # burned-supply balance is later priced as millions and surfaces as a false high-value finding
    from opfor.core import Task, World, Node
    from opfor.scenarios.onchain.assets.contract.capabilities import SweepPools
    from opfor.scenarios.onchain.assets.contract.sources.observations import PoolObservation
    from opfor.scenarios.onchain.seed import Survey

    zero = "0x0000000000000000000000000000000000000000"
    pool = PoolObservation(address=_POOL, chain="ethereum", dex_id="uniswap", url="u",
                           base_address=_TOKEN, base_symbol="PRJ",
                           quote_address=zero, quote_symbol="?", liquidity_usd=90_000.0)
    world = World()
    world.add(Node(id="survey:ethereum", type="survey",
                   payload=Survey(name="t", chain="ethereum")))
    outcome = SweepPools(lambda s: (pool,)).run(Task(capability="sweep_pools", node="survey:ethereum"),
                                                world)
    yielded = {n.payload.address.lower() for f in outcome.facts for n in f.yields}
    assert _TOKEN.lower() in yielded  # the real project token is kept
    assert zero not in yielded  # the null sink is skipped, never a node


def test_triage_drops_a_null_address_even_when_it_reports_funds():
    # defense in depth: a null sink arriving by any path than the sweep is dropped before the model
    from opfor.core import Fact, Node, World
    from opfor.scenarios.onchain.lifecycle.triage import AuditTriage
    from opfor.scenarios.onchain.assets.contract.types import ContractData, FundFact, IdentityFact

    zero = "0x0000000000000000000000000000000000000000"
    world = World()
    nid = f"contract:ethereum:{zero}"
    world.add(Node(id=nid, type="contract",
                   payload=ContractData(chain="ethereum", address=zero, role="unknown")))
    world.absorb([Fact(kind="identified", about=nid, payload=IdentityFact(role="unknown")),
                  Fact(kind="funded", about=nid, payload=FundFact(funds_at_risk_usd=2_000_000))])
    # pruned before any model call, so the mock provider is never consulted
    assert AuditTriage(KNOWLEDGE, provider=MockProvider(), model="m").judge(world) == []


def test_signal_and_guard_scans_are_mechanical():
    detections = load_detections(DETECTIONS)
    risk, central = scan_source(_VAULT_SOURCE, detections.signatures)
    assert "share_accounting" in risk and "dex_spot_price_dependency" in risk
    assert "owner_can_pause" in central
    guarded = guarded_functions(_VAULT_SOURCE, detections.guards)
    assert "pause" in guarded and "deposit" not in guarded

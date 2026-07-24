"""The onchain scenario, driven end to end with injected fixture seams, no network.

These lock the pipeline the scenario serves: a DEX sweep grows pool and token nodes, a pivot
finds the fund contract behind a token, enrichment identifies it and reads its funds, interfaces,
and signals, and triage mints one audit candidate for the fund contract while the bare pool and
token are not audit targets. They also lock the invariant points: judgment is triage's, a bare
pair is downgraded, and the report is contract-centric.
"""

from __future__ import annotations

import json

from opfor.core import Budget, Scope
from opfor.core.engine import run as engine_run
from opfor.core.phase import Phase
from opfor.scenarios import onchain
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


def _run():
    scenario = onchain.build(sweep_fn=_fake_sweep, pivot_fn=_fake_pivot, source_fn=_fake_source,
                             identify_fn=identify_role, funds_fn=_fake_funds)
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
    assert finding.severity == "HIGH"
    assert finding.where == _VAULT
    data = finding.data
    assert data["kind"] == "audit-candidate" and data["priority"] == "A"
    assert data["role"] == "vault"
    assert "deposit" in data["open_fund_paths"]
    assert {"share_accounting", "dex_spot_price_dependency"} <= set(data["risk_flags"])
    # centralization is recorded but did not raise the priority
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


def test_identify_needs_two_markers_so_a_shared_name_does_not_misclassify():
    # a lone deposit is not a vault, two vault markers are
    assert identify_role(Evidence(functions=("deposit",), role_hint="token")) == "token"
    assert identify_role(Evidence(functions=("deposit", "withdraw", "redeem"))) == "vault"


def test_an_anchor_run_audits_the_given_contract_and_skips_the_sweep():
    # a focused run: the operator names a contract to audit, no chain sweep
    scenario = onchain.build(sweep_fn=_fake_sweep, pivot_fn=_fake_pivot, source_fn=_fake_source,
                             identify_fn=identify_role, funds_fn=_fake_funds)
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


def test_signal_and_guard_scans_are_mechanical():
    detections = load_detections(DETECTIONS)
    risk, central = scan_source(_VAULT_SOURCE, detections.signatures)
    assert "share_accounting" in risk and "dex_spot_price_dependency" in risk
    assert "owner_can_pause" in central
    guarded = guarded_functions(_VAULT_SOURCE, detections.guards)
    assert "pause" in guarded and "deposit" not in guarded

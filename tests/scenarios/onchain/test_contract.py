"""The onchain contract-level units, enrichment seams and triage judgment in isolation.

These lock the per-contract behavior underneath the pipeline: funds pricing, discovery, the pivot,
the sweep, address validation, role identification, source signals, and the triage judge including
its adversarial mode, plus the source-adapter rails, the RPC fallback, and the env-tuned throttles.
"""

from __future__ import annotations

import json

import pytest

from tests.scenarios.onchain.fixtures import *

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
        nid = "contract:ethereum:0xabcd000000000000000000000000000000000001"
        world.add(Node(id=nid, type="contract",
                       payload=ContractData(chain="ethereum", address="0xabcd000000000000000000000000000000000001", role="unknown",
                                            source="pivoted", related_to="0xtoken")))
        world.absorb([Fact(kind="sourced", about=nid, payload=SourceFact(verified=False, note="unverified")),
                      Fact(kind="identified", about=nid, payload=IdentityFact(role="unknown")),
                      Fact(kind="funded", about=nid, payload=FundFact(funds_at_risk_usd=funds))])
        return world

    # unverified but $5M: the model surfaces it on the unverified-high-value class
    big = MockProvider(responses=[_reply({"address": "0xabcd000000000000000000000000000000000001", "category": "unverified-high-value",
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
    from opfor.scenarios.onchain.assets.contract.chains import default_chain_policy
    outcome = SweepPools(lambda s: (pool,), default_chain_policy()).run(
        Task(capability="sweep_pools", node="survey:ethereum"), world)
    yielded = {n.payload.address.lower() for f in outcome.facts for n in f.yields}
    assert _TOKEN.lower() in yielded  # the real project token is kept
    assert zero not in yielded  # the null sink is skipped, never a node
    # but it is not dropped silently, it is recorded as a discovery exclusion with its reason,
    # so the run's surface shows what the sweep set aside, invariant 5
    excluded = {i.address.lower(): i.reason for f in outcome.facts if f.kind == "discovery_excluded"
                for i in f.payload.items}
    assert excluded.get(zero) == "null-address"


def test_sweep_skips_a_malformed_pool_address_but_keeps_its_valid_token():
    # a discovery source can hand back a 32-byte pool id instead of a 20-byte address, it must not
    # become a phantom contract node whose funds are pool metadata rather than a real balance
    from opfor.core import Task, World, Node
    from opfor.scenarios.onchain.assets.contract.capabilities import SweepPools
    from opfor.scenarios.onchain.assets.contract.sources.observations import PoolObservation
    from opfor.scenarios.onchain.seed import Survey

    bad_pool_id = "0x19d044e9f31155f162928a04f261ea2af6f811130bbc850398cfaed377d7fdb9"  # 32 bytes
    pool = PoolObservation(address=bad_pool_id, chain="ethereum", dex_id="uniswap", url="u",
                           base_address=_TOKEN, base_symbol="PRJ",
                           quote_address="0xnothex", quote_symbol="?", liquidity_usd=90_000.0)
    world = World()
    world.add(Node(id="survey:ethereum", type="survey",
                   payload=Survey(name="t", chain="ethereum")))
    from opfor.scenarios.onchain.assets.contract.chains import default_chain_policy
    outcome = SweepPools(lambda s: (pool,), default_chain_policy()).run(
        Task(capability="sweep_pools", node="survey:ethereum"), world)
    yielded = {n.payload.address.lower() for f in outcome.facts for n in f.yields}
    assert bad_pool_id.lower() not in yielded  # the 32-byte id is not a node
    assert "0xnothex" not in yielded  # a non-hex token side is dropped too
    assert _TOKEN.lower() in yielded  # the well-formed project token survives
    # the two malformed addresses are recorded excluded, not silently dropped, invariant 5
    excluded = {i.address.lower(): i.reason for f in outcome.facts if f.kind == "discovery_excluded"
                for i in f.payload.items}
    assert excluded.get(bad_pool_id.lower()) == "malformed-address"
    assert excluded.get("0xnothex") == "malformed-address"


def test_is_evm_address_accepts_only_a_20_byte_hex_address():
    from opfor.scenarios.onchain.assets.contract.sources.funds import is_evm_address

    assert is_evm_address("0x" + "a" * 40)
    assert not is_evm_address("0x" + "a" * 64)  # a 32-byte id
    assert not is_evm_address("0x" + "a" * 39)  # too short
    assert not is_evm_address("0xNOTHEXNOTHEXNOTHEXNOTHEXNOTHEXNOTHEX0000")  # non-hex
    assert not is_evm_address("")


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


def _auditable_world(addr="0xffff000000000000000000000000000000000009"):
    """A world with one verified, funded, fund-path-exposing contract, so the base triage pass
    mints a finding the adversarial roles can then weigh."""
    from opfor.core import Fact, Node, World
    from opfor.scenarios.onchain.assets.contract.types import (
        ContractData, FundFact, IdentityFact, InterfaceFact, InterfaceFn, SignalFact, SourceFact,
    )

    world = World()
    nid = f"contract:ethereum:{addr}"
    world.add(Node(id=nid, type="contract",
                   payload=ContractData(chain="ethereum", address=addr, role="vault")))
    world.absorb([
        Fact(kind="sourced", about=nid, payload=SourceFact(verified=True, source_text="x")),
        Fact(kind="identified", about=nid, payload=IdentityFact(role="vault")),
        Fact(kind="funded", about=nid, payload=FundFact(funds_at_risk_usd=1_000_000)),
        Fact(kind="interfaces", about=nid, payload=InterfaceFact(
            functions=(InterfaceFn(name="withdraw", is_fund_path=True, guarded=False),))),
        Fact(kind="signals", about=nid, payload=SignalFact(flags=("share_accounting",))),
    ])
    return world, addr


def _base_reply(addr):
    return _reply({"address": addr, "category": "external-fund-path", "priority": "A",
                   "severity": "HIGH", "title": "vault", "evidence": "funds behind an open path"})


def test_adversarial_challenger_drops_a_refuted_finding():
    from opfor.scenarios.onchain.lifecycle.triage import AuditTriage

    world, addr = _auditable_world()
    base = MockProvider(responses=[_base_reply(addr)])
    challenger = MockProvider(responses=['{"refuted": true, "reason": "a value-token misread"}'])
    triage = AuditTriage(KNOWLEDGE, provider=base, model="m", challenger=challenger)
    assert triage.judge(world) == []  # refuted with no judge, so dropped


def test_adversarial_judge_breaks_the_tie_and_keeps_the_finding():
    from opfor.scenarios.onchain.lifecycle.triage import AuditTriage

    world, addr = _auditable_world()
    base = MockProvider(responses=[_base_reply(addr)])
    challenger = MockProvider(responses=['{"refuted": true, "reason": "maybe a wrapper"}'])
    judge = MockProvider(responses=['{"keep": true, "reason": "the open fund path is real"}'])
    triage = AuditTriage(KNOWLEDGE, provider=base, model="m", challenger=challenger, judge=judge)
    out = triage.judge(world)
    assert len(out) == 1 and out[0].where == addr  # judge overrode the refutation


def test_adversarial_is_recall_safe_when_a_role_call_fails():
    from opfor.scenarios.onchain.lifecycle.triage import AuditTriage

    world, addr = _auditable_world()
    base = MockProvider(responses=[_base_reply(addr)])
    # a challenger with no scripted reply raises on a blank completion, so the finding is kept
    triage = AuditTriage(KNOWLEDGE, provider=base, model="m", challenger=MockProvider())
    assert len(triage.judge(world)) == 1  # a role error never drops a finding


def test_adversarial_mode_wires_the_roles_from_the_env(monkeypatch):
    monkeypatch.setenv("OPFOR_TRIAGE_MODE", "adversarial")
    sc = onchain.build(provider=MockProvider(), model="m", identify_fn=_fake_identify)
    assert sc.triage._challenger is not None and sc.triage._judge is not None
    monkeypatch.setenv("OPFOR_TRIAGE_MODE", "standard")
    sc2 = onchain.build(provider=MockProvider(), model="m", identify_fn=_fake_identify)
    assert sc2.triage._challenger is None and sc2.triage._judge is None


def test_geckoterminal_throttle_and_discovery_breadth_are_tunable(monkeypatch):
    from opfor.scenarios.onchain.assets.contract.sources import geckoterminal as g

    clock = {"t": 100.0}
    slept = []
    monkeypatch.setattr(g.time, "monotonic", lambda: clock["t"])
    monkeypatch.setattr(g.time, "sleep", lambda s: slept.append(s))
    g._next_call[0] = 0.0
    g._throttle(2.1)
    assert slept == []  # the first call schedules the next slot, does not wait
    g._throttle(2.1)
    assert slept and abs(slept[-1] - 2.1) < 0.01  # the second waits out the interval

    # discovery breadth is env-tunable so an operator can widen the sweep for the long tail
    monkeypatch.setenv("OPFOR_ONCHAIN_MAX_POOLS", "40")
    monkeypatch.setenv("OPFOR_ONCHAIN_DISCOVERY_PAGES", "2")
    assert g._max_pools() == 40 and g._pages() == 2
    monkeypatch.delenv("OPFOR_ONCHAIN_MAX_POOLS")
    assert g._max_pools() == g._MAX_POOLS_DEFAULT  # defaults to the small precision-first cap


def test_etherscan_throttle_serializes_calls_to_stay_under_the_rate_limit(monkeypatch):
    from opfor.scenarios.onchain.assets.contract.sources import etherscan

    clock = {"t": 100.0}
    slept = []
    monkeypatch.setattr(etherscan.time, "monotonic", lambda: clock["t"])
    monkeypatch.setattr(etherscan.time, "sleep", lambda s: slept.append(s))
    etherscan._next_call[0] = 0.0
    # the first call does not wait, it only schedules the next slot
    etherscan._etherscan_wait(0.22)
    assert slept == []
    # a second call before the interval has passed blocks until the slot opens
    etherscan._etherscan_wait(0.22)
    assert slept and abs(slept[-1] - 0.22) < 0.01
    # a zero interval disables the throttle, for a paid plan
    slept.clear()
    etherscan._etherscan_wait(0.0)
    assert slept == []


def test_etherscan_fails_loud_on_a_chain_access_denial(monkeypatch):
    # the free tier answers a gated chain's account/proxy module with a status-0 error STRING; read
    # as data it is silently wrong (a codeless address, a zero balance), so it must fail loud
    from opfor.scenarios.onchain.assets.contract.sources import etherscan

    denial = {"status": "0", "message": "NOTOK",
              "result": "Free API access is not supported for this chain. Please upgrade your api plan"}

    class _Resp:
        def read(self): return json.dumps(denial).encode("utf-8")
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr(etherscan, "api_key", lambda: "k")
    monkeypatch.setattr(etherscan, "_etherscan_wait", lambda interval: None)
    monkeypatch.setattr(etherscan.urllib.request, "urlopen", lambda req, timeout=0: _Resp())

    with pytest.raises(RuntimeError):
        etherscan.get("arbitrum", {"module": "account", "action": "tokentx"})
    with pytest.raises(RuntimeError):  # proxy raises too, never returns the error string as a result
        etherscan.proxy("arbitrum", "eth_getCode", {"address": "0x0"})
    # the detector is precise: a legitimate unverified-source status-0 body is NOT a denial
    assert etherscan._access_denied(denial) is True
    assert etherscan._access_denied({"status": "0", "result": "Contract source code not verified"}) is False


def test_etherscan_min_interval_reads_the_env_and_fails_loud_on_a_bad_value(monkeypatch):
    import pytest

    from opfor.scenarios.onchain.assets.contract.sources import etherscan

    monkeypatch.delenv("OPFOR_ETHERSCAN_MIN_INTERVAL", raising=False)
    assert etherscan._min_interval() == float(etherscan._MIN_INTERVAL_DEFAULT)
    monkeypatch.setenv("OPFOR_ETHERSCAN_MIN_INTERVAL", "0")
    assert etherscan._min_interval() == 0.0  # a paid plan disables the throttle
    monkeypatch.setenv("OPFOR_ETHERSCAN_MIN_INTERVAL", "not-a-number")
    # a set-but-unparsable rail fails loud rather than silently reverting to the default, invariant 5
    with pytest.raises(ValueError):
        etherscan._min_interval()


def test_funds_floor_fails_loud_on_a_bad_value(monkeypatch):
    import pytest

    from opfor.scenarios.onchain.report import _funds_floor

    monkeypatch.delenv("OPFOR_ONCHAIN_FUNDS_FLOOR", raising=False)
    assert _funds_floor() == 10000.0
    monkeypatch.setenv("OPFOR_ONCHAIN_FUNDS_FLOOR", "not-a-number")
    with pytest.raises(ValueError):
        _funds_floor()


def test_discovery_age_band_is_env_tunable(monkeypatch):
    # the age band widens via env so an operator can look back a year, defaults keep the young tail
    monkeypatch.delenv("OPFOR_ONCHAIN_MIN_AGE_DAYS", raising=False)
    monkeypatch.delenv("OPFOR_ONCHAIN_MAX_AGE_DAYS", raising=False)
    survey = onchain.seed("t", chain="ethereum").node("survey:ethereum").payload
    assert survey.min_age_days == 2.0 and survey.max_age_days == 45.0  # young-tail default
    monkeypatch.setenv("OPFOR_ONCHAIN_MAX_AGE_DAYS", "365")
    survey = onchain.seed("t", chain="ethereum").node("survey:ethereum").payload
    assert survey.max_age_days == 365.0  # widened to a year


def test_polygon_and_arbitrum_are_wired_across_the_three_config_points():
    # the free Etherscan V2 key covers ethereum, polygon, and arbitrum, so all three must resolve a
    # chainid, a GeckoTerminal network, and a value-token set, or a chain is only half-supported.
    # All three now come from one data file, the chain policy, so this guards a single data edit.
    from opfor.scenarios.onchain.assets.contract.sources import etherscan, geckoterminal
    from opfor.scenarios.onchain.assets.contract.sources.funds import value_token_addresses

    for chain in ("ethereum", "polygon", "arbitrum"):
        assert etherscan.chain_id(chain) is not None, chain  # explorer knows the chainid
        assert geckoterminal._network(chain), chain          # discovery knows the network slug
        assert value_token_addresses(chain), chain           # funds knows the value tokens
    # the native/wrapped token decimals are sane, so a native balance is not mispriced
    assert geckoterminal._network("polygon") == "polygon_pos"  # GeckoTerminal's slug, not "polygon"


def test_rpc_uses_the_explorer_proxy_by_default_and_a_public_node_only_when_configured(monkeypatch):
    from opfor.scenarios.onchain.assets.contract.sources import rpc

    seen = {}
    monkeypatch.setattr(rpc, "_public_call", lambda eps, m, p: seen.__setitem__("public", eps) or "0x")
    monkeypatch.setattr(rpc.etherscan, "proxy", lambda c, m, p: seen.__setitem__("proxy", c) or "0x")

    # the supported chains are fully covered by the explorer key, so they take the proxy path
    assert rpc._public_endpoints("ethereum") == ()
    rpc._call("ethereum", "eth_getCode", {"address": "0xabc", "tag": "latest"})
    assert seen.get("proxy") == "ethereum" and "public" not in seen
    # OPFOR_<CHAIN>_RPC opts a chain into a public node, the escape hatch for a gated chain
    monkeypatch.setenv("OPFOR_ARBITRUM_RPC", "https://my-node")
    assert rpc._public_endpoints("arbitrum")[0] == "https://my-node"
    rpc._call("arbitrum", "eth_getCode", {"address": "0xabc", "tag": "latest"})
    assert seen.get("public")[0] == "https://my-node"


def test_rpc_params_translate_to_json_rpc_positional_form():
    from opfor.scenarios.onchain.assets.contract.sources import rpc

    assert rpc._params_for("eth_getCode", {"address": "0xa", "tag": "latest"}) == ["0xa", "latest"]
    assert rpc._params_for("eth_getStorageAt", {"address": "0xa", "position": "0xs", "tag": "latest"}) \
        == ["0xa", "0xs", "latest"]
    assert rpc._params_for("eth_call", {"to": "0xa", "data": "0xd", "tag": "latest"}) \
        == [{"to": "0xa", "data": "0xd"}, "latest"]


def test_deep_pivot_degrades_to_shallow_when_the_transfer_module_is_gated(monkeypatch):
    import importlib
    pivot = importlib.import_module("opfor.scenarios.onchain.assets.contract.sources.pivot")
    from opfor.scenarios.onchain.assets.contract.sources import etherscan

    monkeypatch.setattr(pivot.etherscan, "configured", lambda chain: True)
    def _denied(chain, params):
        raise etherscan.AccessDenied("gated on this chain")
    monkeypatch.setattr(pivot.etherscan, "get", _denied)
    # a gated transfer module yields no transfers rather than raising, so the pivot keeps its shallow
    # pools instead of failing the whole step; a non-denial error still propagates (not caught here)
    assert pivot._etherscan_transfers("0xtoken", "arbitrum") == []


def test_signal_and_guard_scans_are_mechanical():
    detections = load_detections(DETECTIONS)
    risk, central = scan_source(_VAULT_SOURCE, detections.signatures)
    assert "share_accounting" in risk and "dex_spot_price_dependency" in risk
    assert "owner_can_pause" in central
    guarded = guarded_functions(_VAULT_SOURCE, detections.guards)
    assert "pause" in guarded and "deposit" not in guarded

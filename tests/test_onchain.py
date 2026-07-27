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
                             identify_fn=_fake_identify, funds_fn=_fake_funds,
                             resolve_fn=lambda addr, chain: "", provider=provider)
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
    # the provenance breadcrumb names the world facts the verdict was judged from, so a reader can
    # trace it to the observations rather than the model's word alone
    assert {"identified", "funded"} <= set(data["sources"])


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


def test_report_tags_and_sorts_known_infrastructure_out_of_the_audit_targets():
    from opfor.core import Fact, Node, World
    from opfor.scenarios.onchain.report import contract_records
    from opfor.scenarios.onchain.assets.contract.types import ContractData, FundFact, IdentityFact

    infra = "0x000000000004444c5dc75cb358380d2e3de08a90"  # Uniswap V4 PoolManager, on the denylist
    target = "0xabcd000000000000000000000000000000000042"
    world = World()
    for addr, role in ((infra, "router"), (target, "vault")):
        nid = f"contract:ethereum:{addr}"
        world.add(Node(id=nid, type="contract",
                       payload=ContractData(chain="ethereum", address=addr, role=role)))
        world.absorb([Fact(kind="identified", about=nid, payload=IdentityFact(role=role))])
    # the infrastructure holds far more, but must not float to the top of the target queue
    world.absorb([Fact(kind="funded", about=f"contract:ethereum:{infra}",
                       payload=FundFact(funds_at_risk_usd=200_000_000))])
    world.absorb([Fact(kind="funded", about=f"contract:ethereum:{target}",
                       payload=FundFact(funds_at_risk_usd=50_000))])

    records = {r["address"]: r for r in contract_records(world, [])}
    assert records[infra]["audit_target"] is False and records[infra]["excluded"] == "known-infrastructure"
    assert records[target]["audit_target"] is True and "excluded" not in records[target]
    # the $50k target sorts above the $200M infrastructure, funds no longer promote the noise
    order = [r["address"] for r in contract_records(world, [])]
    assert order.index(target) < order.index(infra)


def test_report_source_state_is_three_valued_not_a_misleading_bool():
    from opfor.core import Fact, Node, World
    from opfor.scenarios.onchain.report import contract_records
    from opfor.scenarios.onchain.assets.contract.types import (
        ContractData, FundFact, IdentityFact, SourceFact,
    )

    verified = "0xaaaa000000000000000000000000000000000001"
    unverified = "0xbbbb000000000000000000000000000000000002"
    pool = "0xcccc000000000000000000000000000000000003"
    world = World()
    for addr, role in ((verified, "vault"), (unverified, "vault"), (pool, "pool")):
        nid = f"contract:ethereum:{addr}"
        world.add(Node(id=nid, type="contract",
                       payload=ContractData(chain="ethereum", address=addr, role=role,
                                            liquidity_usd=100_000.0)))
        world.absorb([Fact(kind="identified", about=nid, payload=IdentityFact(role=role)),
                      Fact(kind="funded", about=nid, payload=FundFact(funds_at_risk_usd=100_000))])
    # the vaults were fetched, the pool was never fetched (it skips ENRICH)
    world.absorb([Fact(kind="sourced", about=f"contract:ethereum:{verified}",
                       payload=SourceFact(verified=True, source_text="x")),
                  Fact(kind="sourced", about=f"contract:ethereum:{unverified}",
                       payload=SourceFact(verified=False))])

    r = {c["address"]: c for c in contract_records(world, [])}
    assert r[verified]["source_state"] == "verified" and r[verified]["source_auditable"] is True
    assert r[unverified]["source_state"] == "unverified" and r[unverified]["source_auditable"] is False
    # the never-fetched pool is `not_fetched`, not a misleading `unverified`, the old bool's bug
    assert r[pool]["source_state"] == "not_fetched" and r[pool]["source_auditable"] is False
    # the unverified contract is still worth a look, just not on the source-audit queue
    assert r[unverified]["audit_target"] is True


def test_funds_floor_drops_the_long_tail_but_keeps_a_finding():
    from opfor.core import Fact, Node, World
    from opfor.scenarios.onchain.report import contract_records
    from opfor.scenarios.onchain.assets.contract.types import ContractData, FundFact, IdentityFact
    from opfor.core.result import Finding

    dust = "0xaaaa000000000000000000000000000000000010"      # tiny balance, no finding
    dust_hit = "0xbbbb000000000000000000000000000000000011"  # tiny balance, but a finding
    world = World()
    for addr in (dust, dust_hit):
        nid = f"contract:ethereum:{addr}"
        world.add(Node(id=nid, type="contract",
                       payload=ContractData(chain="ethereum", address=addr, role="vault")))
        world.absorb([Fact(kind="identified", about=nid, payload=IdentityFact(role="vault")),
                      Fact(kind="funded", about=nid, payload=FundFact(funds_at_risk_usd=500))])

    finding = Finding(id="finding:x", title="t", severity="LOW", where=dust_hit, evidence="e", data={})
    r = {c["address"]: c for c in contract_records(world, [finding])}
    assert r[dust]["audit_target"] is False and r[dust]["excluded"] == "below-funds-floor"
    assert r[dust_hit]["audit_target"] is True  # a finding is kept whatever its balance, recall first


def test_ranking_does_not_let_funds_alone_promote_an_opaque_contract():
    from opfor.core import Fact, Node, World
    from opfor.scenarios.onchain.report import contract_records
    from opfor.scenarios.onchain.assets.contract.types import (
        ContractData, FundFact, IdentityFact, SignalFact, SourceFact,
    )

    lean = "0xaaaa000000000000000000000000000000000020"   # verified, signal-rich, $20k
    whale = "0xbbbb000000000000000000000000000000000021"  # unverified, no signals, $5M
    world = World()
    for addr, verified, funds in ((lean, True, 20_000), (whale, False, 5_000_000)):
        nid = f"contract:ethereum:{addr}"
        world.add(Node(id=nid, type="contract",
                       payload=ContractData(chain="ethereum", address=addr, role="vault")))
        world.absorb([Fact(kind="identified", about=nid, payload=IdentityFact(role="vault")),
                      Fact(kind="funded", about=nid, payload=FundFact(funds_at_risk_usd=funds)),
                      Fact(kind="sourced", about=nid, payload=SourceFact(verified=verified, source_text="x" if verified else ""))])
    world.absorb([Fact(kind="signals", about=f"contract:ethereum:{lean}",
                       payload=SignalFact(flags=("share_accounting", "dex_spot_price_dependency")))])

    order = [c["address"] for c in contract_records(world, [])]
    # the verified, signal-rich $20k target ranks above the opaque $5M one, funds is not the lead key
    assert order.index(lean) < order.index(whale)


def test_resolve_proxy_brings_the_implementation_in_as_a_contract():
    from opfor.core import Task, World, Node
    from opfor.scenarios.onchain.assets.contract.capabilities import ResolveProxy
    from opfor.scenarios.onchain.assets.contract.types import ContractData

    proxy = "0x230f1e241c621d5af670dad83ebcdd18971e2995"
    impl = "0x98b3f0db84ca50a776f7cc340f429198c917f6f1"
    world = World()
    nid = f"contract:ethereum:{proxy}"
    world.add(Node(id=nid, type="contract",
                   payload=ContractData(chain="ethereum", address=proxy, role="proxy")))
    outcome = ResolveProxy(lambda addr, chain: impl).run(
        Task(capability="resolve_proxy", node=nid), world)
    yielded = [n for f in outcome.facts for n in f.yields]
    assert any(f.kind == "impl_resolved" for f in outcome.facts)  # recorded so the rule stops
    assert len(yielded) == 1
    node = yielded[0]
    assert node.payload.address == impl and node.payload.source == "implementation"
    assert node.payload.related_to == proxy  # the impl points back to the proxy for ranking

    # a non-proxy or an empty slot yields no implementation node, but still records the fact
    empty = ResolveProxy(lambda addr, chain: "").run(Task(capability="resolve_proxy", node=nid), world)
    assert [n for f in empty.facts for n in f.yields] == []
    assert any(f.kind == "impl_resolved" for f in empty.facts)


def test_implementation_address_reads_the_low_20_bytes_of_the_slot(monkeypatch):
    from opfor.scenarios.onchain.assets.contract.sources import rpc

    impl = "98b3f0db84ca50a776f7cc340f429198c917f6f1"
    word = "0x" + impl.rjust(64, "0")  # a 32-byte word, address in the low 20 bytes
    monkeypatch.setattr(rpc.etherscan, "proxy", lambda chain, action, params: word)
    assert rpc.implementation_address("0xproxy", "ethereum") == "0x" + impl
    # a zero slot means not a proxy, so no implementation
    monkeypatch.setattr(rpc.etherscan, "proxy", lambda chain, action, params: "0x" + "0" * 64)
    assert rpc.implementation_address("0xproxy", "ethereum") == ""


def test_report_ranks_a_proxy_implementation_ahead_of_a_richer_plain_target():
    from opfor.core import Fact, Node, World
    from opfor.scenarios.onchain.report import contract_records
    from opfor.scenarios.onchain.assets.contract.types import ContractData, FundFact, IdentityFact, SourceFact

    impl = "0xaaaa000000000000000000000000000000000030"    # a proxy implementation, modest funds
    plain = "0xbbbb000000000000000000000000000000000031"   # a plain verified target, richer
    world = World()
    world.add(Node(id=f"contract:ethereum:{impl}", type="contract",
                   payload=ContractData(chain="ethereum", address=impl, role="vault",
                                        source="implementation", related_to="0xproxy")))
    world.add(Node(id=f"contract:ethereum:{plain}", type="contract",
                   payload=ContractData(chain="ethereum", address=plain, role="vault", source="pivoted")))
    for addr, funds in ((impl, 50_000), (plain, 500_000)):
        nid = f"contract:ethereum:{addr}"
        world.absorb([Fact(kind="identified", about=nid, payload=IdentityFact(role="vault")),
                      Fact(kind="funded", about=nid, payload=FundFact(funds_at_risk_usd=funds)),
                      Fact(kind="sourced", about=nid, payload=SourceFact(verified=True, source_text="x"))])

    order = [c["address"] for c in contract_records(world, [])]
    assert order.index(impl) < order.index(plain)  # the implementation leads despite less funds
    rec = {c["address"]: c for c in contract_records(world, [])}
    assert rec[impl]["proxy_implementation"] is True and rec[plain]["proxy_implementation"] is False


def test_a_zero_balance_proxy_implementation_survives_the_funds_floor():
    from opfor.core import Fact, Node, World
    from opfor.scenarios.onchain.report import contract_records
    from opfor.scenarios.onchain.assets.contract.types import ContractData, FundFact, IdentityFact, SourceFact

    # a proxy implementation holds no funds itself, they live in the proxy, so the floor must not
    # drop the very code the proxy resolution brought in to audit
    impl = "0xaaaa000000000000000000000000000000000040"
    world = World()
    nid = f"contract:ethereum:{impl}"
    world.add(Node(id=nid, type="contract",
                   payload=ContractData(chain="ethereum", address=impl, role="unknown",
                                        source="implementation", related_to="0xproxy")))
    world.absorb([Fact(kind="identified", about=nid, payload=IdentityFact(role="unknown")),
                  Fact(kind="funded", about=nid, payload=FundFact(funds_at_risk_usd=0)),
                  Fact(kind="sourced", about=nid, payload=SourceFact(verified=True, source_text="x"))])

    rec = {c["address"]: c for c in contract_records(world, [])}
    assert rec[impl]["audit_target"] is True and "excluded" not in rec[impl]


def test_a_proxy_implementation_read_as_a_token_is_not_dex_layer_excluded():
    # an upgradeable token's implementation the model reads as `token` is still logic worth auditing,
    # not a raw swept pair, so the dex-layer exclusion must not drop the code proxy resolution found
    from opfor.scenarios.onchain.assets.contract.targeting import structural_exclusion

    addr = "0x98b3f0db84ca50a776f7cc340f429198c917f6f1"
    assert structural_exclusion("ethereum", addr, "token", None) == "dex-layer"  # a swept token
    assert structural_exclusion("ethereum", addr, "token", None, is_implementation=True) is None


def test_fingerprint_drops_vendored_files_and_hashes_own_code():
    from opfor.scenarios.onchain.assets.contract.fingerprint import fingerprint
    import json

    source = json.dumps({"sources": {
        "src/Vault.sol": {"content": "contract Vault { function withdraw() external {} }"},
        "@openzeppelin/contracts/token/ERC20.sol": {"content": "contract ERC20 {}"},
        "lib/v4-core/Currency.sol": {"content": "library Currency {}"},
    }})
    own_hashes, own_files, vendored_files = fingerprint("{" + source + "}")  # explorer double-brace wrap
    assert own_files == 1 and vendored_files == 2  # only Vault.sol is the project's own code
    assert len(own_hashes) == 1

    # a source that is entirely third-party libraries has no own code
    allvendor = json.dumps({"sources": {"@openzeppelin/a.sol": {"content": "contract A {}"},
                                        "solmate/b.sol": {"content": "contract B {}"}}})
    _, own, vend = fingerprint(allvendor)
    assert own == 0 and vend == 2


def test_report_clusters_two_deployments_of_one_project_into_one_target():
    from opfor.core import Fact, Node, World
    from opfor.scenarios.onchain.report import contract_records
    from opfor.scenarios.onchain.assets.contract.types import (
        ContractData, CodebaseFact, FundFact, IdentityFact, SourceFact,
    )

    token = "0xaaaa000000000000000000000000000000000050"    # the project token, smaller
    rewards = "0xbbbb000000000000000000000000000000000051"  # its rewards contract, richer, inlines the token
    world = World()
    for addr, funds, hashes in ((token, 100_000, ("tokensrc",)),
                                (rewards, 900_000, ("tokensrc", "rewardsrc"))):
        nid = f"contract:ethereum:{addr}"
        world.add(Node(id=nid, type="contract",
                       payload=ContractData(chain="ethereum", address=addr, role="vault")))
        world.absorb([Fact(kind="identified", about=nid, payload=IdentityFact(role="vault")),
                      Fact(kind="funded", about=nid, payload=FundFact(funds_at_risk_usd=funds)),
                      Fact(kind="sourced", about=nid, payload=SourceFact(verified=True, source_text="x")),
                      Fact(kind="codebase", about=nid, payload=CodebaseFact(own_hashes=hashes, own_files=len(hashes)))])

    recs = {c["address"]: c for c in contract_records(world, [])}
    # both share the token source hash, so they are one project, the richer one is the primary
    assert recs[token]["project"] == rewards and recs[rewards]["project"] == rewards
    assert recs[rewards]["project_primary"] is True and recs[token]["project_primary"] is False
    # the secondary member sorts below the primary, so the queue shows one target per project first
    order = [c["address"] for c in contract_records(world, [])]
    assert order.index(rewards) < order.index(token)


def test_a_vendored_contract_is_excluded_from_the_audit_targets():
    from opfor.core import Fact, Node, World
    from opfor.scenarios.onchain.report import contract_records
    from opfor.scenarios.onchain.lifecycle.triage import AuditTriage
    from opfor.scenarios.onchain.assets.contract.types import (
        ContractData, CodebaseFact, FundFact, IdentityFact, InterfaceFact, InterfaceFn, SignalFact, SourceFact,
    )

    addr = "0xcccc000000000000000000000000000000000052"
    world = World()
    nid = f"contract:ethereum:{addr}"
    world.add(Node(id=nid, type="contract",
                   payload=ContractData(chain="ethereum", address=addr, role="unknown")))
    world.absorb([Fact(kind="identified", about=nid, payload=IdentityFact(role="unknown")),
                  Fact(kind="funded", about=nid, payload=FundFact(funds_at_risk_usd=500_000)),
                  Fact(kind="sourced", about=nid, payload=SourceFact(verified=True, source_text="x")),
                  Fact(kind="interfaces", about=nid, payload=InterfaceFact(
                      functions=(InterfaceFn(name="withdraw", is_fund_path=True, guarded=False),))),
                  Fact(kind="signals", about=nid, payload=SignalFact(flags=("share_accounting",))),
                  Fact(kind="codebase", about=nid, payload=CodebaseFact(vendored=True, vendored_files=3))])

    rec = {c["address"]: c for c in contract_records(world, [])}[addr]
    assert rec["audit_target"] is False and rec["excluded"] == "vendored-library"
    # triage never even judges it, a dependency copy is not a project's own code to audit
    assert AuditTriage(KNOWLEDGE, provider=MockProvider(), model="m").judge(world) == []


def test_a_hub_is_flagged_prioritized_and_exempt_from_the_funds_floor():
    from opfor.core import Fact, Node, World
    from opfor.scenarios.onchain.report import contract_records
    from opfor.scenarios.onchain.assets.contract.types import ContractData, FundFact, IdentityFact, SourceFact

    hub = "0xaaaa000000000000000000000000000000000060"    # many contracts pivoted from it, near zero
    plain = "0xbbbb000000000000000000000000000000000061"  # a richer plain target
    spokes = [f"0xcccc0000000000000000000000000000000000{i:02x}" for i in range(2)]
    world = World()
    for addr, funds in ((hub, 100), (plain, 500_000)):
        nid = f"contract:ethereum:{addr}"
        world.add(Node(id=nid, type="contract",
                       payload=ContractData(chain="ethereum", address=addr, role="unknown")))
        world.absorb([Fact(kind="identified", about=nid, payload=IdentityFact(role="unknown")),
                      Fact(kind="funded", about=nid, payload=FundFact(funds_at_risk_usd=funds)),
                      Fact(kind="sourced", about=nid, payload=SourceFact(verified=True, source_text="x"))])
    # two spoke contracts were pivoted from the hub, making it a shared origin
    for s in spokes:
        world.add(Node(id=f"contract:ethereum:{s}", type="contract",
                       payload=ContractData(chain="ethereum", address=s, role="unknown", related_to=hub)))

    rec = {c["address"]: c for c in contract_records(world, [])}
    assert rec[hub]["hub"] is True and rec[hub]["hub_refs"] == 2
    # the $100 hub survives the funds floor and outranks the $500k plain target on its centrality
    assert rec[hub]["audit_target"] is True and "excluded" not in rec[hub]
    order = [c["address"] for c in contract_records(world, [])]
    assert order.index(hub) < order.index(plain)


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


def test_role_fingerprints_load_and_render_for_the_identify_prompt():
    from opfor.scenarios.onchain.assets.contract.roles import load_roles, render_roles

    roles = load_roles(KNOWLEDGE / "technologies")
    by_role = {fp.role: fp for fp in roles}
    assert "vault" in by_role and "staking" in by_role and "farm" in by_role
    assert "deposit" in by_role["vault"].markers  # a marker function rode in from the data file
    rendered = render_roles(roles)
    assert "Known role fingerprints" in rendered
    assert "vault:" in rendered and "stake" in rendered  # the guide names roles and their markers


def test_missing_technologies_dir_yields_no_fingerprints(tmp_path):
    from opfor.scenarios.onchain.assets.contract.roles import load_roles, render_roles

    # a thin knowledge tree identifies on the seam's own vocabulary rather than failing
    assert load_roles(tmp_path / "nope") == ()
    assert render_roles(()) == ""


def test_identify_rides_the_role_fingerprints_into_the_model_prompt():
    from opfor.scenarios.onchain.assets.contract.roles import load_roles, render_roles

    reference = render_roles(load_roles(KNOWLEDGE / "technologies"))
    provider = MockProvider(responses=['{"role": "staking"}'])
    role = identify_role(provider, "m", Evidence(functions=("stake", "getReward")),
                         role_reference=reference)
    assert role == "staking"
    # the fingerprints reached the model as the reference guide, not a fixed table in code
    assert "Known role fingerprints" in provider.calls[0]["system"]


def test_an_anchor_run_audits_the_given_contract_and_skips_the_sweep():
    # a focused run: the operator names a contract to audit, no chain sweep
    provider = MockProvider(responses=[_reply(_VAULT_VERDICT)])
    scenario = onchain.build(sweep_fn=_fake_sweep, pivot_fn=_fake_pivot, source_fn=_fake_source,
                             identify_fn=_fake_identify, funds_fn=_fake_funds,
                             resolve_fn=lambda addr, chain: "", provider=provider)
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

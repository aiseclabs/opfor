"""The onchain scenario driven end to end, the whole-run pipeline and the contract-centric report.

These lock the pipeline the scenario serves: a DEX sweep grows pool and token nodes, a pivot finds
the fund contract behind a token, enrichment identifies it and reads its funds, interfaces, and
signals, and triage mints one audit candidate for the fund contract while the bare pool and token
are not audit targets. They also lock the report ranking, exclusion, proxy resolution, and
clustering, and the anchor run that judges named contracts without a sweep.
"""

from __future__ import annotations

import json

import pytest

from tests.scenarios.onchain.fixtures import *

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
        ContractData, CodebaseFact, FundFact, IdentityFact, InterfaceFact, InterfaceFunction, SignalFact, SourceFact,
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
                      functions=(InterfaceFunction(name="withdraw", is_fund_path=True, guarded=False),))),
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

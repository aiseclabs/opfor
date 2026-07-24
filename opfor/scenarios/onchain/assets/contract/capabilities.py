"""The contract class capabilities, one tool each, raw facts only, no judgment.

MAP grows the contract set, `sweep_pools` reads the active DEX pools and `pivot_related` finds
the fund contracts behind a token or pool. ENRICH analyzes each contract, `fetch_source` pulls
verified source and ABI, `identify_contract` classifies the role, `read_funds` reads the funds,
`enum_interfaces` lists the exposed functions, and `scan_signals` matches the risk patterns. Every
capability reports what it observed, whether a contract is worth auditing is triage's call,
invariant 2. Every source is public, so every capability is osint, more passive than an HTTP
probe since no request reaches a target's own servers.
"""

from __future__ import annotations

from opfor.core import Capability, Done, Fact, Failed, Node, Outcome, Phase, Task, World
from opfor.scenarios.onchain.assets.contract.identify import Evidence
from opfor.scenarios.onchain.assets.contract.signals import (
    Detections,
    guarded_functions,
    scan_source,
)
from opfor.scenarios.onchain.assets.contract.types import (
    ContractData,
    FundFact,
    IdentityFact,
    InterfaceFact,
    InterfaceFn,
    SignalFact,
    SourceFact,
)


def _node_id(chain: str, address: str) -> str:
    return f"contract:{chain}:{address.lower()}"


def _net_failed(what: str, exc: Exception) -> Failed:
    """A public-source read that errored. Marked transient so the engine retries a blip a bounded
    number of times, and it fails loud rather than returning an empty clean result, invariant 5."""
    return Failed(reason=f"{what}: {type(exc).__name__}: {exc}", transient=True)


class SweepPools(Capability):
    """MAP: read the active DEX pools for the survey's chain, as pool and token contract nodes."""

    name = "sweep_pools"
    phase = Phase.MAP
    osint = True

    def __init__(self, sweep_fn) -> None:
        self._sweep = sweep_fn

    def run(self, task: Task, world: World) -> Outcome:
        survey = world.node(task.node).payload
        try:
            pools = self._sweep(survey)
        except Exception as exc:
            return _net_failed("dex sweep", exc)
        nodes: list[Node] = []
        for pool in pools:
            nodes.append(Node(id=_node_id(pool.chain, pool.address), type="contract",
                              payload=ContractData(chain=pool.chain, address=pool.address,
                                                   role="pool", source="swept", dex_id=pool.dex_id,
                                                   url=pool.url, base_symbol=pool.base_symbol,
                                                   quote_symbol=pool.quote_symbol,
                                                   liquidity_usd=pool.liquidity_usd,
                                                   age_days=pool.age_days)))
            for address, symbol in ((pool.base_address, pool.base_symbol),
                                    (pool.quote_address, pool.quote_symbol)):
                if address:
                    nodes.append(Node(id=_node_id(pool.chain, address), type="contract",
                                      payload=ContractData(chain=pool.chain, address=address,
                                                           role="token", source="swept",
                                                           base_symbol=symbol,
                                                           age_days=pool.age_days)))
        return Done(facts=(Fact(kind="swept", about=task.node, yields=tuple(nodes)),))


class PivotRelated(Capability):
    """MAP: find the fund-management contracts behind a token or pool, the step that leaves the
    raw pair layer for the vault, staking, farm, router, or locker actually worth auditing."""

    name = "pivot_related"
    phase = Phase.MAP
    osint = True

    def __init__(self, pivot_fn) -> None:
        self._pivot = pivot_fn

    def run(self, task: Task, world: World) -> Outcome:
        contract = world.node(task.node).payload
        try:
            related = self._pivot(contract)
        except Exception as exc:
            return _net_failed("pivot", exc)
        nodes = tuple(
            Node(id=_node_id(rel.chain, rel.address), type="contract",
                 payload=ContractData(chain=rel.chain, address=rel.address, role=rel.role_hint,
                                      source="pivoted", related_to=contract.address))
            for rel in related if rel.address
        )
        return Done(facts=(Fact(kind="related", about=task.node, yields=nodes),))


class FetchSource(Capability):
    """ENRICH: pull verified source and ABI from the explorer for one contract."""

    name = "fetch_source"
    phase = Phase.ENRICH
    osint = True

    def __init__(self, source_fn) -> None:
        self._source = source_fn

    def run(self, task: Task, world: World) -> Outcome:
        contract = world.node(task.node).payload
        try:
            obs = self._source(contract)
        except Exception as exc:
            return _net_failed("explorer source", exc)
        fact = SourceFact(verified=obs.verified, functions=tuple(obs.functions),
                          source_text=obs.source_text, note=obs.note)
        return Done(facts=(Fact(kind="sourced", about=task.node, payload=fact),))


class IdentifyContract(Capability):
    """ENRICH: classify a contract's role from its source and functions, via the identify seam."""

    name = "identify_contract"
    phase = Phase.ENRICH
    osint = True

    def __init__(self, identify_fn) -> None:
        self._identify = identify_fn

    def run(self, task: Task, world: World) -> Outcome:
        node = world.node(task.node)
        sourced = world.latest("sourced", node.id)
        functions = sourced.payload.functions if sourced is not None else ()
        source_text = sourced.payload.source_text if sourced is not None else ""
        evidence = Evidence(functions=functions, source_text=source_text,
                            role_hint=node.payload.role)
        role = self._identify(evidence)
        return Done(facts=(Fact(kind="identified", about=node.id,
                                payload=IdentityFact(role=role, evidence="functions and source")),))


class ReadFunds(Capability):
    """ENRICH: read the funds a contract manages, reusing the DEX liquidity as a hint for a pool."""

    name = "read_funds"
    phase = Phase.ENRICH
    osint = True

    def __init__(self, funds_fn) -> None:
        self._funds = funds_fn

    def run(self, task: Task, world: World) -> Outcome:
        contract = world.node(task.node).payload
        try:
            obs = self._funds(contract, contract.liquidity_usd)
        except Exception as exc:
            return _net_failed("funds read", exc)
        fact = FundFact(funds_at_risk_usd=obs.funds_at_risk_usd, assets=tuple(obs.assets),
                        note=obs.note)
        return Done(facts=(Fact(kind="funded", about=task.node, payload=fact),))


class EnumInterfaces(Capability):
    """ENRICH: list the exposed functions from the ABI, tagging fund-path names and guarded ones.

    It reads the source fact rather than the network, so it holds no seam. The fund-path
    vocabulary and the guard keywords are the class's detection data, applied mechanically.
    """

    name = "enum_interfaces"
    phase = Phase.ENRICH
    osint = True

    def __init__(self, detections: Detections) -> None:
        self._detections = detections

    def run(self, task: Task, world: World) -> Outcome:
        sourced = world.latest("sourced", task.node)
        if sourced is None:
            return Done(facts=(Fact(kind="interfaces", about=task.node,
                                    payload=InterfaceFact()),))
        guarded = guarded_functions(sourced.payload.source_text, self._detections.guards)
        functions = tuple(
            InterfaceFn(name=name, is_fund_path=name.lower() in self._detections.fund_paths,
                        guarded=name in guarded)
            for name in sourced.payload.functions
        )
        return Done(facts=(Fact(kind="interfaces", about=task.node,
                                payload=InterfaceFact(functions=functions)),))


class ScanSignals(Capability):
    """ENRICH: match the risk-pattern signatures against the verified source, mechanically.

    It reads the source fact, so it holds no seam. The signatures are the class's detection data.
    Whether a matched flag makes the contract worth auditing is triage's, never decided here.
    """

    name = "scan_signals"
    phase = Phase.ENRICH
    osint = True

    def __init__(self, detections: Detections) -> None:
        self._detections = detections

    def run(self, task: Task, world: World) -> Outcome:
        sourced = world.latest("sourced", task.node)
        source_text = sourced.payload.source_text if sourced is not None else ""
        risk, central = scan_source(source_text, self._detections.signatures)
        return Done(facts=(Fact(kind="signals", about=task.node,
                                payload=SignalFact(flags=risk, centralization=central)),))

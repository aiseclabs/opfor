"""Chainscout executors: discover BSC contracts, enrich them, package candidates.

Four narrow capabilities, one public source each, plus a final packaging step:

- `chainscout_seed`    DeFiLlama -> a batch of `evm_contract` targets (the seed).
- `chainscout_risk`    GoPlus    -> per-contract risk flags.
- `chainscout_meta`    Etherscan -> verified? which compiler? a proxy?
- `chainscout_assess`  package the value + risk + meta a contract accumulated
                       into one candidate Finding, no network.

Every executor only fetches and structures. None of them decides whether a
contract is worth attacking or whether a flag means a real bug, that judgment is
the planner's (which candidate to escalate, at what priority) and triage's
(confirmed / false-positive), so invariants 1 and 2 hold. A source that errors or
returns nothing becomes a loud `*_failed` fact, never a silent clean result
(invariant 5).

All work here is a passive read of a public API about a public contract; nothing
touches the contract itself. So every task the planner emits is osint recon tier,
which scope waves through without per-contract authorization.
"""

from __future__ import annotations

import os

from opfor.model import Fact, Finding, Observation, Target
from opfor.plugins.base import Executor
from opfor.scenarios.chainscout import sources
from opfor.scenarios.chainscout.sources import HttpGet


def _etherscan_key() -> str:
    """The Etherscan V2 key, from the environment only, never a CLI arg."""
    return (
        os.environ.get("CHAINSCOUT_ETHERSCAN_API_KEY")
        or os.environ.get("CODEJURY_ETHERSCAN_API_KEY")
        or ""
    )


def _target(task, graph) -> Target:
    for t in graph.targets():
        if t.id == task.target:
            return t
    raise KeyError(f"no target {task.target!r} in graph")


def _contract_id(chain: str, address: str) -> str:
    return f"evm_contract:{chain}:{address.lower()}"


class _ChainscoutExecutor(Executor):
    """Shared: hold the injected HTTP getter."""

    def __init__(self, get: HttpGet | None = None) -> None:
        self._get = get or sources.http_get


class SeedExecutor(_ChainscoutExecutor):
    """DeFiLlama -> candidate `evm_contract` targets, richest chain-TVL first."""

    capability = "chainscout_seed"

    def run(self, task, graph) -> Observation:
        seed = _target(task, graph)
        chain = str(seed.props.get("chain", ""))
        min_tvl = float(seed.props.get("min_tvl", 0) or 0)
        top_n = int(seed.props.get("top_n", 0) or 0)
        raw = {"seed_id": seed.id, "chain": chain, "min_tvl": min_tvl, "top_n": top_n}
        try:
            raw["protocols"] = sources.defillama_protocols(
                self._get, chain, min_tvl=min_tvl, top_n=top_n
            )
        except Exception as exc:  # network, JSON, or an unsupported chain
            raw["error"] = f"{type(exc).__name__}: {exc}"
        return Observation(entrypoint_id=task.id, action=self.capability, raw=raw)

    def perceive(self, observation) -> list[Fact]:
        raw = observation.raw
        seed_id = raw["seed_id"]
        chain = raw["chain"]
        if "error" in raw:
            return [Fact(kind="chainscout_seed_failed", about=seed_id,
                         data={"chain": chain, "reason": raw["error"]})]
        protocols = raw["protocols"]
        yields = tuple(
            Target(
                id=_contract_id(chain, p["address"]),
                kind="evm_contract",
                props={
                    "chain": chain, "address": p["address"], "name": p["name"],
                    "slug": p["slug"], "category": p["category"], "tvl": p["tvl"],
                    "source": "defillama", "base_url": _contract_id(chain, p["address"]),
                },
            )
            for p in protocols
        )
        return [Fact(kind="chainscout_seeded", about=seed_id,
                     data={"chain": chain, "count": len(yields)}, yields=yields)]


class RiskExecutor(_ChainscoutExecutor):
    """GoPlus -> the risk flags a contract trips (raw, no weighting)."""

    capability = "chainscout_risk"

    def run(self, task, graph) -> Observation:
        target = _target(task, graph)
        chain = str(target.props["chain"])
        address = str(target.props["address"])
        raw = {"target_id": target.id, "chain": chain, "address": address}
        try:
            raw["security"] = sources.goplus_token_security(self._get, chain, address)
        except Exception as exc:
            raw["error"] = f"{type(exc).__name__}: {exc}"
        return Observation(entrypoint_id=task.id, action=self.capability, raw=raw)

    def perceive(self, observation) -> list[Fact]:
        raw = observation.raw
        target_id = raw["target_id"]
        if "error" in raw:
            return [Fact(kind="chainscout_risk_failed", about=target_id,
                         data={"reason": raw["error"]})]
        security = raw["security"]
        flags = sources.tripped_flags(security)
        return [Fact(kind="chainscout_risk", about=target_id, data={
            "risk_flags": flags,
            "covered": bool(security),  # GoPlus had a record for this address
        })]


class MetaExecutor(_ChainscoutExecutor):
    """Etherscan V2 -> verification, compiler, proxy metadata."""

    capability = "chainscout_meta"

    def run(self, task, graph) -> Observation:
        target = _target(task, graph)
        chain = str(target.props["chain"])
        address = str(target.props["address"])
        raw = {"target_id": target.id, "chain": chain, "address": address}
        key = _etherscan_key()
        if not key:
            raw["error"] = "no Etherscan API key (set CHAINSCOUT_ETHERSCAN_API_KEY)"
            return Observation(entrypoint_id=task.id, action=self.capability, raw=raw)
        try:
            raw["meta"] = sources.etherscan_source_meta(self._get, key, chain, address)
        except Exception as exc:
            raw["error"] = f"{type(exc).__name__}: {exc}"
        return Observation(entrypoint_id=task.id, action=self.capability, raw=raw)

    def perceive(self, observation) -> list[Fact]:
        raw = observation.raw
        target_id = raw["target_id"]
        if "error" in raw:
            return [Fact(kind="chainscout_meta_failed", about=target_id,
                         data={"reason": raw["error"]})]
        meta = raw["meta"]
        return [Fact(kind="chainscout_meta", about=target_id, data={
            "verified": meta["verified"],
            "contract_name": meta["contract_name"],
            "compiler_version": meta["compiler_version"],
            "is_proxy": meta["is_proxy"],
            "implementation": meta["implementation"],
            "license": meta["license"],
        })]


class AssessExecutor(_ChainscoutExecutor):
    """Package one contract's value + risk + meta into a candidate Finding.

    This runs no tool; it reads the facts the enrichment stages left on the graph
    and shapes them into a single candidate for triage. It applies no threshold
    and asserts no verdict, the priority band is decided by the planner (passed in
    as a task param) and the real / false-positive call is triage's.
    """

    capability = "chainscout_assess"

    def run(self, task, graph) -> Observation:
        target = _target(task, graph)
        chain = str(target.props["chain"])
        address = str(target.props["address"])
        risk = _latest(graph, "chainscout_risk", target.id)
        meta = _latest(graph, "chainscout_meta", target.id)
        raw = {
            "target_id": target.id,
            "chain": chain,
            "address": address,
            "name": str(target.props.get("name", "")),
            "tvl": target.props.get("tvl"),
            "category": str(target.props.get("category", "")),
            "risk_flags": (risk or {}).get("risk_flags", []),
            "risk_covered": (risk or {}).get("covered", False),
            "verified": (meta or {}).get("verified"),
            "compiler_version": (meta or {}).get("compiler_version", ""),
            "is_proxy": (meta or {}).get("is_proxy"),
            "severity": str(task.params.get("severity", "info")),
        }
        return Observation(entrypoint_id=task.id, action=self.capability, raw=raw)

    def perceive(self, observation) -> list[Fact]:
        raw = observation.raw
        chain, address = raw["chain"], raw["address"]
        explorer = sources.chain_info(chain)["explorer"] + address
        finding = Finding(
            id=f"finding:chainscout:{chain}:{address}",
            props={
                "title": f"Audit candidate: {raw['name'] or address} on {chain}",
                "severity": raw["severity"],
                "where": f"{chain}:{address}",
                "url": explorer,
                "evidence": _evidence(raw),
                "body_snippet": _evidence(raw),
                # Structured axes so the operator can sort value vs risk.
                "chain": chain, "address": address, "name": raw["name"],
                "tvl": raw["tvl"], "category": raw["category"],
                "risk_flags": raw["risk_flags"], "risk_covered": raw["risk_covered"],
                "verified": raw["verified"], "compiler_version": raw["compiler_version"],
                "is_proxy": raw["is_proxy"],
            },
        )
        return [Fact(kind="chainscout_candidate", about=raw["target_id"],
                     data={"finding": finding.id, "severity": raw["severity"]},
                     yields=(finding,))]


def _latest(graph, kind: str, about: str) -> dict | None:
    """The data of the most recent fact of `kind` about `about`, or None."""
    found = None
    for f in graph.facts():
        if f.kind == kind and f.about == about:
            found = f.data
    return found


def _evidence(raw: dict) -> str:
    tvl = raw.get("tvl")
    tvl_str = f"${tvl:,.0f} TVL" if isinstance(tvl, (int, float)) else "TVL unknown"
    verified = raw.get("verified")
    ver_str = "unverified source" if verified is False else (
        f"verified ({raw.get('compiler_version') or 'compiler unknown'})" if verified else "verification unknown"
    )
    flags = raw.get("risk_flags") or []
    flag_str = ("risk flags: " + ", ".join(flags)) if flags else "no GoPlus risk flags"
    proxy_str = "proxy" if raw.get("is_proxy") else "non-proxy"
    return f"{tvl_str}; {ver_str}; {proxy_str}; {flag_str}"


def default_executors(get: HttpGet | None = None) -> dict[str, Executor]:
    return {
        "chainscout_seed": SeedExecutor(get=get),
        "chainscout_risk": RiskExecutor(get=get),
        "chainscout_meta": MetaExecutor(get=get),
        "chainscout_assess": AssessExecutor(get=get),
    }

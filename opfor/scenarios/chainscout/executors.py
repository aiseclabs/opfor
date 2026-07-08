"""Chainscout executors: discover BSC contracts, enrich them, package candidates.

Five narrow capabilities, one source each (plus a final packaging step):

- `chainscout_seed`    Moralis holders -> `evm_contract` targets that hold value.
- `chainscout_age`     Moralis first tx -> when the contract was created.
- `chainscout_meta`    Etherscan       -> verified? which compiler? a proxy? name?
- `chainscout_risk`    GoPlus          -> per-contract risk flags.
- `chainscout_assess`  package the value + age + meta + risk a contract
                       accumulated into one candidate Finding, no network.

Every executor only fetches and structures. None of them decides whether a
contract is worth attacking, whether it is a standard template, or whether a flag
means a real bug, that judgment is the planner's (which candidate to escalate, at
what priority band) and triage's (confirmed / false-positive), so invariants 1
and 2 hold. A source that errors or returns nothing becomes a loud `*_failed`
fact, never a silent clean result (invariant 5).

All work here is a passive read of a public API about a public contract; nothing
touches the contract itself. So every task the planner emits is osint recon tier,
which scope waves through without per-contract authorization.
"""

from __future__ import annotations

import os
from datetime import date, datetime, timezone

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


def _moralis_key() -> str:
    """The Moralis key, from the environment only, never a CLI arg."""
    return os.environ.get("CHAINSCOUT_MORALIS_API_KEY") or ""


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
    """Moralis holders -> `evm_contract` targets that actually hold value.

    The seed is a token basket, a USD band, and a page cap (all campaign data).
    A contract that is a large holder of a major asset is where the money on BSC
    physically sits, so this finds fund-holding contracts, not just token
    addresses. The value band is a gate here; recency and custom-vs-template
    decide priority later.
    """

    capability = "chainscout_seed"

    def run(self, task, graph) -> Observation:
        seed = _target(task, graph)
        chain = str(seed.props.get("chain", ""))
        tokens = [str(t).lower() for t in (seed.props.get("tokens") or [])]
        min_usd = float(seed.props.get("min_usd", 0) or 0)
        max_usd = float(seed.props.get("max_usd", 0) or 0)
        max_pages = int(seed.props.get("max_pages", 0) or 0)
        raw = {
            "seed_id": seed.id, "chain": chain,
            "window_days": int(seed.props.get("window_days", 0) or 0),
            "as_of": str(seed.props.get("as_of", "")),
        }
        key = _moralis_key()
        if not key:
            raw["error"] = "no Moralis API key (set CHAINSCOUT_MORALIS_API_KEY)"
            return Observation(entrypoint_id=task.id, action=self.capability, raw=raw)
        if not tokens:
            raw["error"] = "seed has no tokens to scan"
            return Observation(entrypoint_id=task.id, action=self.capability, raw=raw)
        try:
            found = sources.moralis_value_contracts(
                self._get, key, chain, tokens,
                min_usd=min_usd, max_usd=max_usd, max_pages=max_pages)
            raw["contracts"] = found["contracts"]
            raw["truncated"] = found["truncated"]
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
        contracts = raw["contracts"]
        yields = tuple(
            Target(
                id=_contract_id(chain, addr),
                kind="evm_contract",
                props={
                    "chain": chain, "address": addr,
                    "value_usd": entry["usd"], "tokens": entry["tokens"],
                    "moralis_label": entry["label"], "moralis_entity": entry["entity"],
                    "source": "moralis",
                    # Copied onto each contract so the age stage can date it against
                    # the same window/reference the operator set on the seed.
                    "window_days": raw["window_days"], "as_of": raw["as_of"],
                    "base_url": _contract_id(chain, addr),
                },
            )
            for addr, entry in contracts.items()
        )
        return [Fact(kind="chainscout_seeded", about=seed_id, data={
            "chain": chain, "count": len(yields),
            # Loud coverage note: these tokens still had in-band holders at the
            # page cap, so the list is bounded, not complete (invariant 5).
            "truncated_tokens": raw["truncated"],
        }, yields=yields)]


class AgeExecutor(_ChainscoutExecutor):
    """Moralis first transaction -> the contract's creation date and its age."""

    capability = "chainscout_age"

    def run(self, task, graph) -> Observation:
        target = _target(task, graph)
        chain = str(target.props["chain"])
        address = str(target.props["address"])
        raw = {
            "target_id": target.id, "chain": chain, "address": address,
            "window_days": int(target.props.get("window_days", 0) or 0),
            "as_of": str(target.props.get("as_of", "")),
        }
        key = _moralis_key()
        if not key:
            raw["error"] = "no Moralis API key (set CHAINSCOUT_MORALIS_API_KEY)"
            return Observation(entrypoint_id=task.id, action=self.capability, raw=raw)
        try:
            born = sources.moralis_first_seen(self._get, key, chain, address)
            raw["born_ts"] = born["born_ts"]
            raw["born_block"] = born["born_block"]
        except Exception as exc:
            raw["error"] = f"{type(exc).__name__}: {exc}"
        return Observation(entrypoint_id=task.id, action=self.capability, raw=raw)

    def perceive(self, observation) -> list[Fact]:
        raw = observation.raw
        target_id = raw["target_id"]
        if "error" in raw:
            return [Fact(kind="chainscout_age_failed", about=target_id,
                         data={"reason": raw["error"]})]
        age_days, fresh = _age_and_fresh(
            raw.get("born_ts"), raw["as_of"], raw["window_days"])
        return [Fact(kind="chainscout_age", about=target_id, data={
            "born_ts": raw.get("born_ts"), "born_block": raw.get("born_block"),
            "age_days": age_days, "fresh": fresh,
        })]


class MetaExecutor(_ChainscoutExecutor):
    """Etherscan V2 -> verification, compiler, proxy, and contract-name metadata."""

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


class AssessExecutor(_ChainscoutExecutor):
    """Package one contract's value + age + meta + risk into a candidate Finding.

    This runs no tool; it reads the facts the enrichment stages left on the graph
    and shapes them into a single candidate for triage. It applies no threshold
    and asserts no verdict, the priority band (`severity`) and the "why" signals
    are decided by the planner (passed in as task params) and the real /
    false-positive call is triage's.
    """

    capability = "chainscout_assess"

    def run(self, task, graph) -> Observation:
        target = _target(task, graph)
        chain = str(target.props["chain"])
        address = str(target.props["address"])
        age = _latest(graph, "chainscout_age", target.id)
        meta = _latest(graph, "chainscout_meta", target.id)
        risk = _latest(graph, "chainscout_risk", target.id)
        raw = {
            "target_id": target.id, "chain": chain, "address": address,
            "value_usd": target.props.get("value_usd"),
            "tokens": target.props.get("tokens", {}),
            "moralis_label": target.props.get("moralis_label"),
            "name": (meta or {}).get("contract_name", ""),
            "born_ts": (age or {}).get("born_ts"),
            "age_days": (age or {}).get("age_days"),
            "fresh": (age or {}).get("fresh", False),
            "verified": (meta or {}).get("verified"),
            "compiler_version": (meta or {}).get("compiler_version", ""),
            "is_proxy": (meta or {}).get("is_proxy"),
            "risk_flags": (risk or {}).get("risk_flags", []),
            "risk_covered": (risk or {}).get("covered", False),
            "severity": str(task.params.get("severity", "info")),
            "signals": list(task.params.get("signals", [])),
        }
        return Observation(entrypoint_id=task.id, action=self.capability, raw=raw)

    def perceive(self, observation) -> list[Fact]:
        raw = observation.raw
        chain, address = raw["chain"], raw["address"]
        explorer = sources.chain_info(chain)["explorer"] + address
        name = raw["name"] or "unverified"
        finding = Finding(
            id=f"finding:chainscout:{chain}:{address}",
            props={
                "title": f"Recon candidate: {name} on {chain} (${_usd(raw['value_usd'])})",
                "severity": raw["severity"],
                "where": f"{chain}:{address}",
                "url": explorer,
                "evidence": _evidence(raw),
                "body_snippet": _evidence(raw),
                # Structured axes so the operator can sort value / recency / risk.
                "chain": chain, "address": address, "name": raw["name"],
                "value_usd": raw["value_usd"], "tokens": raw["tokens"],
                "moralis_label": raw["moralis_label"],
                "born_ts": raw["born_ts"], "age_days": raw["age_days"],
                "fresh": raw["fresh"], "signals": raw["signals"],
                "verified": raw["verified"], "compiler_version": raw["compiler_version"],
                "is_proxy": raw["is_proxy"],
                "risk_flags": raw["risk_flags"], "risk_covered": raw["risk_covered"],
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


def _age_and_fresh(born_ts, as_of: str, window_days: int) -> tuple[int | None, bool]:
    """Age in days from creation to the reference date, and whether it is fresh.

    The reference date is the seed's `as_of` when set (so a run is reproducible),
    otherwise today in UTC. Fresh means deployed within `window_days` of it.
    """
    if not born_ts:
        return None, False
    try:
        born = date.fromisoformat(str(born_ts)[:10])
    except ValueError:
        return None, False
    ref = _reference_date(as_of)
    age_days = (ref - born).days
    fresh = window_days > 0 and 0 <= age_days <= window_days
    return age_days, fresh


def _reference_date(as_of: str) -> date:
    if as_of:
        try:
            return date.fromisoformat(str(as_of)[:10])
        except ValueError:
            pass
    return datetime.now(timezone.utc).date()


def _usd(value) -> str:
    return f"{value:,.0f}" if isinstance(value, (int, float)) else "?"


def _evidence(raw: dict) -> str:
    value = raw.get("value_usd")
    tokens = raw.get("tokens") or {}
    val_str = f"${_usd(value)} across {len(tokens)} asset(s)" if tokens else "value unknown"
    age = raw.get("age_days")
    age_str = f"deployed {age}d ago" if isinstance(age, int) else "age unknown"
    verified = raw.get("verified")
    ver_str = "unverified source" if verified is False else (
        f"verified {raw.get('name') or ''}".strip() if verified else "verification unknown"
    )
    proxy_str = "proxy" if raw.get("is_proxy") else "non-proxy"
    label = raw.get("moralis_label")
    label_str = f"; labelled {label}" if label else ""
    flags = raw.get("risk_flags") or []
    flag_str = ("; risk flags: " + ", ".join(flags)) if flags else ""
    return f"{val_str}; {age_str}; {ver_str}; {proxy_str}{label_str}{flag_str}"


def default_executors(get: HttpGet | None = None) -> dict[str, Executor]:
    return {
        "chainscout_seed": SeedExecutor(get=get),
        "chainscout_age": AgeExecutor(get=get),
        "chainscout_meta": MetaExecutor(get=get),
        "chainscout_risk": RiskExecutor(get=get),
        "chainscout_assess": AssessExecutor(get=get),
    }

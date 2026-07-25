"""The contract-centric report view, the run's world rendered as one record per contract.

The findings list answers which contracts are worth auditing and why. This answers the run's
own shape, the pipeline the scenario serves, which contracts were discovered, what each one is,
the funds it manages, the interfaces it exposes, and the risk signals matched against it. It
reads only the world the engine mutated, no model, so it is a faithful record of what the run
observed, and it folds each finding onto the contract it sits on. The generic report in the CLI
merges this in, so the CLI holds no scenario specifics.
"""

from __future__ import annotations

import os
from typing import Any

from opfor.core import World
from opfor.scenarios.onchain.assets.contract import KNOWLEDGE
from opfor.scenarios.onchain.assets.contract.known import load_known_infrastructure
from opfor.scenarios.onchain.assets.contract.targeting import structural_exclusion

# The funds below which a contract that carries no finding is not an audit target, so the long tail
# of near-zero-balance deploys does not take an audit slot from a real one, the plan's floor. A
# finding is kept whatever its balance, recall stays first. `OPFOR_ONCHAIN_FUNDS_FLOOR` tunes it.
_FUNDS_FLOOR_DEFAULT = "10000"


def _funds_floor() -> float:
    """The audit-target funds floor, read at the call so a changed environment is seen. A
    non-numeric value falls back to the default rather than failing the report."""
    raw = os.environ.get("OPFOR_ONCHAIN_FUNDS_FLOOR", _FUNDS_FLOOR_DEFAULT)
    try:
        return max(0.0, float(raw))
    except ValueError:
        return float(_FUNDS_FLOOR_DEFAULT)


def _interfaces(interfaces_fact) -> list[dict]:
    """The exposed fund-path functions and whether each is guarded, so the reachable surface is
    visible even where no finding was minted. A non fund-path function is omitted to keep the
    record about the money paths."""
    if interfaces_fact is None:
        return []
    out = [{"name": fn.name, "guarded": fn.guarded}
           for fn in interfaces_fact.payload.functions if fn.is_fund_path]
    return sorted(out, key=lambda record: record["name"])


def contract_records(world: World, findings, known_infrastructure=None) -> list[dict]:
    """One record per discovered contract that reached a state worth reporting, carrying what it
    is and the state of its funds and interfaces, with its findings folded in by address.

    Each record is tagged `audit_target`, whether it is a candidate an operator should look at, and
    when it is not, `excluded` names the structural reason. The tag uses the same filter triage
    judges by, so the audit targets a reader selects match the queue triage produced rather than
    diverging from it. Known infrastructure and the raw DEX layer stay in the inventory as a
    faithful record of what the run saw, but are marked and sorted below the targets, not silently
    dropped and not surfaced at the top by their large balance."""
    known = load_known_infrastructure(KNOWLEDGE) if known_infrastructure is None \
        else known_infrastructure
    floor = _funds_floor()
    findings_by_address: dict[str, list[str]] = {}
    for finding in findings:
        findings_by_address.setdefault(finding.where.lower(), []).append(finding.id)

    records: list[dict] = []
    for node in world.nodes("contract"):
        payload = node.payload
        identified = world.latest("identified", node.id)
        role = identified.payload.role if identified is not None else payload.role
        funded = world.latest("funded", node.id)
        # A fund contract carries a priced funds fact. A pool is not enriched, so it falls back to
        # the liquidity the sweep saw, keeping it in the inventory without spending ENRICH on it.
        funds = funded.payload.funds_at_risk_usd if funded is not None else payload.liquidity_usd
        signals = world.latest("signals", node.id)
        risk_flags = list(signals.payload.flags) if signals is not None else []
        central = list(signals.payload.centralization) if signals is not None else []
        interfaces = _interfaces(world.latest("interfaces", node.id))
        finding_ids = findings_by_address.get(payload.address.lower(), [])
        # The source state is three-valued, not a bool, so a contract that was never fetched is not
        # reported as unverified. A pool skips ENRICH, so its source is `not_fetched`, which is why
        # the old bool read a canonical, verified pair as unverified. A source audit needs
        # `verified`, `unverified` is the opaque high-value queue, and `not_fetched` is neither.
        sourced = world.latest("sourced", node.id)
        if sourced is None:
            source_state = "not_fetched"
        elif sourced.payload.verified:
            source_state = "verified"
        else:
            source_state = "unverified"
        # A resolved proxy implementation is where the audited logic actually lives, so it is flagged
        # and ranked high among the targets, the correction over auditing the thin forwarding shell.
        is_impl = payload.source == "implementation"
        # A contract earns a record when it holds funds, carries a finding, exposes a fund path, or
        # matched a signal, so the report lists the surface that matters, not every swept token. A
        # proxy implementation earns one too, its logic is the target even when its own balance is
        # zero, so the resolution's result is never dropped before it is even recorded.
        if not (funds > 0 or finding_ids or interfaces or risk_flags or is_impl):
            continue
        excluded = structural_exclusion(payload.chain, payload.address, role, known,
                                        is_implementation=is_impl)
        # Below the funds floor and carrying no finding, a contract is not worth an audit slot, so it
        # is excluded like the structural cases, after them so a structural reason wins the label. A
        # proxy implementation is exempt, its funds live in the proxy it stands behind, not in itself,
        # so its own near-zero balance must not drop the very code the proxy resolution brought in.
        if excluded is None and not finding_ids and funds < floor and not is_impl:
            excluded = "below-funds-floor"
        # A contract that carries a finding is a target whatever its structure, triage minted it, so
        # a finding always wins over a structural exclusion rather than being hidden by it.
        audit_target = bool(finding_ids) or excluded is None
        record: dict[str, Any] = {
            "chain": payload.chain,
            "address": payload.address,
            "role": role,
            "source": payload.source,
            "source_state": source_state,
            "source_auditable": source_state == "verified",
            "funds_at_risk_usd": round(funds, 2),
            "audit_target": audit_target,
            "proxy_implementation": is_impl,
        }
        if not audit_target and excluded is not None:
            record["excluded"] = excluded
        if payload.related_to:
            record["related_to"] = payload.related_to
        if interfaces:
            record["fund_paths"] = interfaces
        if risk_flags:
            record["risk_flags"] = risk_flags
        if central:
            record["centralization_flags"] = central
        if finding_ids:
            record["findings"] = finding_ids
        records.append(record)
    # The ranking, deliberately not by funds first. Funds correlate with the most-audited public
    # infrastructure, so a pure balance sort promotes the least productive targets, the defect the
    # target-selection analysis found. Instead: audit targets first, then the finding-bearing, then
    # resolved proxy implementations, the code behind the funds, then the source-auditable, then the
    # signal-rich, and only then the richest, with funds as the last discriminator. The excluded
    # inventory sorts last however large its balance.
    def _rank(record: dict) -> tuple:
        signal_richness = len(record.get("risk_flags", [])) + len(record.get("fund_paths", []))
        return (not record["audit_target"], not record.get("findings"),
                not record.get("proxy_implementation"), not record.get("source_auditable"),
                -signal_richness, -record["funds_at_risk_usd"], record["address"])

    return sorted(records, key=_rank)


def report_view(world: World, findings) -> dict:
    """The scenario's structured report contribution, the `contracts` section the CLI merges into
    the run's findings.json. Keyed so a reader, or a later scenario, adds sections without
    collision."""
    return {"contracts": contract_records(world, findings)}

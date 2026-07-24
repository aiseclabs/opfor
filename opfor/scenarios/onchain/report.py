"""The contract-centric report view, the run's world rendered as one record per contract.

The findings list answers which contracts are worth auditing and why. This answers the run's
own shape, the pipeline the scenario serves, which contracts were discovered, what each one is,
the funds it manages, the interfaces it exposes, and the risk signals matched against it. It
reads only the world the engine mutated, no model, so it is a faithful record of what the run
observed, and it folds each finding onto the contract it sits on. The generic report in the CLI
merges this in, so the CLI holds no scenario specifics.
"""

from __future__ import annotations

from typing import Any

from opfor.core import World


def _interfaces(interfaces_fact) -> list[dict]:
    """The exposed fund-path functions and whether each is guarded, so the reachable surface is
    visible even where no finding was minted. A non fund-path function is omitted to keep the
    record about the money paths."""
    if interfaces_fact is None:
        return []
    out = [{"name": fn.name, "guarded": fn.guarded}
           for fn in interfaces_fact.payload.functions if fn.is_fund_path]
    return sorted(out, key=lambda record: record["name"])


def contract_records(world: World, findings) -> list[dict]:
    """One record per discovered contract that reached a state worth reporting, carrying what it
    is and the state of its funds and interfaces, with its findings folded in by address."""
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
        sourced = world.latest("sourced", node.id)
        verified = bool(sourced is not None and sourced.payload.verified)
        # A contract earns a record when it holds funds, carries a finding, exposes a fund path, or
        # matched a signal, so the report lists the surface that matters, not every swept token.
        if not (funds > 0 or finding_ids or interfaces or risk_flags):
            continue
        record: dict[str, Any] = {
            "chain": payload.chain,
            "address": payload.address,
            "role": role,
            "source": payload.source,
            "source_verified": verified,
            "funds_at_risk_usd": round(funds, 2),
        }
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
    # The contracts that carry a finding come first, then the richest by funds, then the rest by
    # address, so a reader meets the audit queue before the quiet inventory.
    return sorted(records, key=lambda record: (not record.get("findings"),
                                               -record["funds_at_risk_usd"], record["address"]))


def report_view(world: World, findings) -> dict:
    """The scenario's structured report contribution, the `contracts` section the CLI merges into
    the run's findings.json. Keyed so a reader, or a later scenario, adds sections without
    collision."""
    return {"contracts": contract_records(world, findings)}

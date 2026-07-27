"""The contract-centric report view, the run's world rendered as one record per contract.

The findings list answers which contracts are worth auditing and why. This answers the run's
own shape, the pipeline the scenario serves, which contracts were discovered, what each one is,
the funds it manages, the interfaces it exposes, and the risk signals matched against it. It
reads only the world the engine mutated, no model, so it is a faithful record of what the run
observed, and it folds each finding onto the contract it sits on. The generic report in the CLI
merges this in, so the CLI holds no scenario specifics.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from opfor.core import World
from opfor.scenarios.onchain.env import env_float
from opfor.scenarios.onchain.assets.contract import KNOWLEDGE
from opfor.scenarios.onchain.assets.contract.known import load_known_infrastructure
from opfor.scenarios.onchain.assets.contract.targeting import structural_exclusion

# The funds below which a contract that carries no finding is not an audit target, so the long tail
# of near-zero-balance deploys does not take an audit slot from a real one, the plan's floor. A
# finding is kept whatever its balance, recall stays first. `OPFOR_ONCHAIN_FUNDS_FLOOR` tunes it.
_FUNDS_FLOOR_DEFAULT = 10000.0


def _funds_floor() -> float:
    """The audit-target funds floor, read at the call so a changed environment is seen. A
    set-but-unparsable value fails loud rather than silently using the default, so an operator
    never believes a different floor is in force than the run applied, invariant 5."""
    return env_float("OPFOR_ONCHAIN_FUNDS_FLOOR", _FUNDS_FLOOR_DEFAULT, minimum=0.0)


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
    # A hub is a contract many others were pivoted from, a shared point of activity worth a closer
    # look, the analysis's most-suspicious-hub. Count the references once, so a contract that is the
    # origin of two or more others is flagged and prioritized, and exempt from the funds floor since
    # its interest is its centrality, not its own balance.
    hub_refs = Counter(node.payload.related_to.lower()
                       for node in world.nodes("contract") if node.payload.related_to)
    own_by_address: dict[str, tuple[str, ...]] = {}
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
        # The codebase fingerprint, so two deployments of one project cluster as one target and a
        # pure dependency copy is dropped. `own_hashes` are its own source files, used to cluster.
        codebase = world.latest("codebase", node.id)
        own_hashes = codebase.payload.own_hashes if codebase is not None else ()
        is_vendored = codebase is not None and codebase.payload.vendored
        # A contract earns a record when it holds funds, carries a finding, exposes a fund path, or
        # matched a signal, so the report lists the surface that matters, not every swept token. A
        # proxy implementation earns one too, its logic is the target even when its own balance is
        # zero, so the resolution's result is never dropped before it is even recorded.
        if not (funds > 0 or finding_ids or interfaces or risk_flags or is_impl):
            continue
        refs = hub_refs.get(payload.address.lower(), 0)
        is_hub = refs >= 2
        excluded = structural_exclusion(payload.chain, payload.address, role, known,
                                        is_implementation=is_impl, is_vendored=is_vendored)
        # Below the funds floor and carrying no finding, a contract is not worth an audit slot, so it
        # is excluded like the structural cases, after them so a structural reason wins the label. A
        # proxy implementation and a hub are exempt, an implementation's funds live in its proxy and a
        # hub's interest is its centrality, so a near-zero balance must not drop either.
        if excluded is None and not finding_ids and funds < floor and not is_impl and not is_hub:
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
        if is_hub:
            record["hub"] = True
            record["hub_refs"] = refs
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
        if own_hashes:
            own_by_address[payload.address] = own_hashes
    # Cluster the records that share own source files into projects, so a project deployed as two
    # contracts counts as one target and its secondary members sort below the primary.
    _cluster_projects(records, own_by_address)
    # The ranking, deliberately not by funds first. Funds correlate with the most-audited public
    # infrastructure, so a pure balance sort promotes the least productive targets, the defect the
    # target-selection analysis found. Instead: audit targets first, then the finding-bearing, then
    # resolved proxy implementations and hubs, the code behind the funds and the shared points of
    # activity, then the source-auditable, then the signal-rich, and only then the richest, with
    # funds as the last discriminator. The excluded inventory sorts last however large its balance.
    def _rank(record: dict) -> tuple:
        signal_richness = len(record.get("risk_flags", [])) + len(record.get("fund_paths", []))
        is_secondary = record.get("project") is not None and not record.get("project_primary", True)
        return (not record["audit_target"], is_secondary, not record.get("findings"),
                not record.get("proxy_implementation"), not record.get("hub"),
                not record.get("source_auditable"), -signal_richness,
                -record["funds_at_risk_usd"], record["address"])

    return sorted(records, key=_rank)


def _cluster_projects(records: list[dict], own_by_address: dict[str, tuple[str, ...]]) -> None:
    """Group records that share an own source file into one project, mutating each grouped record
    with a `project` id, the primary member's address, and `project_primary`. Two deployments of one
    project, a token and its rewards contract, share their own files, so they cluster and the report
    counts them as one target with its duplicate sorted below, not as two. A single-member group is
    not a project and gets no tag. Vendored files are already dropped before the hashes, so a shared
    library does not merge unrelated projects."""
    hash_to_addrs: dict[str, list[str]] = {}
    for addr, hashes in own_by_address.items():
        for h in hashes:
            hash_to_addrs.setdefault(h, []).append(addr)

    parent = {addr: addr for addr in own_by_address}

    def find(a: str) -> str:
        while parent[a] != a:
            parent[a] = parent[parent[a]]
            a = parent[a]
        return a

    for addrs in hash_to_addrs.values():
        for other in addrs[1:]:
            parent[find(addrs[0])] = find(other)

    groups: dict[str, list[str]] = {}
    for addr in own_by_address:
        groups.setdefault(find(addr), []).append(addr)

    by_address = {r["address"]: r for r in records}
    for members in groups.values():
        recs = [by_address[a] for a in members if a in by_address]
        if len(recs) < 2:
            continue
        # The primary is the member worth showing for the project, an audit target over an excluded
        # one, then a finding-bearing over a quiet one, then the richest, so the group's real target
        # leads and its duplicates fold under it rather than an excluded member taking the lead.
        primary = sorted(recs, key=lambda r: (not r.get("audit_target"), not r.get("findings"),
                                              -r["funds_at_risk_usd"], r["address"]))[0]
        for r in recs:
            r["project"] = primary["address"]
            r["project_primary"] = r["address"] == primary["address"]


def _discovery_excluded(world: World) -> list[dict]:
    """The observations the sweep saw and set aside, one record per address with its reason, so the
    report shows what discovery dropped rather than a silent gap, invariant 5. Deduped across
    surveys by address, since a value token is set aside on every chain it quotes."""
    seen: dict[str, dict] = {}
    for node in world.nodes("survey"):
        fact = world.latest("discovery_excluded", node.id)
        if fact is None:
            continue
        for item in fact.payload.items:
            seen.setdefault(item.address.lower(), {
                "chain": item.chain, "address": item.address,
                "symbol": item.symbol, "reason": item.reason})
    return sorted(seen.values(), key=lambda r: (r["reason"], r["address"]))


def report_view(world: World, findings) -> dict:
    """The scenario's structured report contribution, the `contracts` section the CLI merges into
    the run's findings.json. Keyed so a reader, or a later scenario, adds sections without
    collision. The `discovery_excluded` section names what the sweep set aside and why, so a
    money token or a burn sink is a visible exclusion, not a silent drop."""
    view = {"contracts": contract_records(world, findings)}
    excluded = _discovery_excluded(world)
    if excluded:
        view["discovery_excluded"] = excluded
    return view

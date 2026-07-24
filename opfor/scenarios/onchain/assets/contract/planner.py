"""Contract-class planner rules, the sweep-then-pivot discovery and the enrich pipeline.

MAP sweeps the survey's active pools, then pivots each token or pool to the fund contracts
behind it. ENRICH fetches source, then in parallel identifies the role, reads funds, enumerates
interfaces, and scans signals, each gated on the source fact so a contract with no verified
source is not analyzed as if it had one. Rules gate on facts, not on task order, so a re-emitted
task is harmless and a stage waits for its predecessor without a task dependency.
"""

from __future__ import annotations

from opfor.core import Task, World, each

CLASS = "contract"

# A pivot runs only from a token, the thing a fund contract sits behind. A pool is the leaf a
# token pointed at, so it is not pivoted, and a contract already pivoted from something is not
# pivoted again, so the walk is one hop, bounded.
_PIVOTABLE_ROLES = ("token",)
# A pool is not an audit target and is never enriched, it exists only to spawn its token nodes and
# sit in the inventory. Enriching it would spend the budget on source and balances triage discards.
_SKIP_ENRICH_ROLES = ("pool",)


def _pivot_rule(world: World) -> list[Task]:
    """Pivot each swept token to the fund contracts behind it, once per token."""
    tasks: list[Task] = []
    for node in world.nodes("contract"):
        if node.payload.role not in _PIVOTABLE_ROLES:
            continue
        if world.has_fact(node.id, "related"):
            continue
        tasks.append(Task(capability="pivot_related", node=node.id))
    return tasks


def _fetch_rule(world: World) -> list[Task]:
    """Fetch source for each contract that is not a skipped leaf and lacks it."""
    tasks: list[Task] = []
    for node in world.nodes("contract"):
        if node.payload.role in _SKIP_ENRICH_ROLES:
            continue
        if world.has_fact(node.id, "sourced"):
            continue
        tasks.append(Task(capability="fetch_source", node=node.id))
    return tasks


def _after_source_rule(world: World, capability: str, unless_fact: str) -> list[Task]:
    """Run a capability on each contract that has been sourced but not yet carries `unless_fact`,
    so the enrich step waits for source without a task dependency."""
    tasks: list[Task] = []
    for node in world.nodes("contract"):
        if not world.has_fact(node.id, "sourced"):
            continue
        if world.has_fact(node.id, unless_fact):
            continue
        tasks.append(Task(capability=capability, node=node.id))
    return tasks


def _identify_rule(world: World) -> list[Task]:
    return _after_source_rule(world, "identify_contract", "identified")


def _funds_rule(world: World) -> list[Task]:
    """Read funds after the role is identified, so the funds read knows what it is reading."""
    tasks: list[Task] = []
    for node in world.nodes("contract"):
        if not world.has_fact(node.id, "identified"):
            continue
        if world.has_fact(node.id, "funded"):
            continue
        tasks.append(Task(capability="read_funds", node=node.id))
    return tasks


def _interfaces_rule(world: World) -> list[Task]:
    return _after_source_rule(world, "enum_interfaces", "interfaces")


def _signals_rule(world: World) -> list[Task]:
    return _after_source_rule(world, "scan_signals", "signals")


def map_rules() -> list:
    """The contract MAP rules, sweep the survey then pivot each token or pool. The sweep runs only
    when the survey names no anchors, so a focused anchor run audits exactly the given contracts
    rather than sweeping the whole chain."""
    return [
        each("survey", run="sweep_pools", unless_fact="swept", where=lambda s: not s.anchors),
        _pivot_rule,
    ]


def enrich_rules() -> list:
    """The contract ENRICH rules, fetch source then analyze. The four analyses gate on the source
    fact, so they run as soon as a contract is sourced and in any order among themselves."""
    return [
        _fetch_rule,
        _identify_rule,
        _funds_rule,
        _interfaces_rule,
        _signals_rule,
    ]

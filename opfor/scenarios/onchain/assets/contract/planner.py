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

# A pivot runs only from a token or a pool, the layer that has a fund contract behind it. A
# contract already pivoted from something is not pivoted again, so the walk is one hop, bounded.
_PIVOTABLE_ROLES = ("pool", "token")


def _pivot_rule(world: World) -> list[Task]:
    """Pivot each swept token or pool to the fund contracts behind it, once per contract."""
    tasks: list[Task] = []
    for node in world.nodes("contract"):
        if node.payload.role not in _PIVOTABLE_ROLES:
            continue
        if world.has_fact(node.id, "related"):
            continue
        tasks.append(Task(capability="pivot_related", node=node.id))
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
        each("contract", run="fetch_source", unless_fact="sourced"),
        _identify_rule,
        _funds_rule,
        _interfaces_rule,
        _signals_rule,
    ]

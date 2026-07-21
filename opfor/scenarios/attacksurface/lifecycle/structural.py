"""The structural findings triage mints outside the model.

Each is a deterministic run-completeness or inventory rule, not a semantic verdict, so it
stays in code rather than in the model pass. Gathering them here keeps the set of what triage
mints without asking the model auditable at a glance, and keeps the triage judge itself about
the model call. Every function takes the world and returns findings, holding no state.

`STRUCTURAL` is the inventory and coverage set the judge runs unconditionally.
`resolution_caveat` is separate, since it also short-circuits the model pass when the resolver
is down, so the judge treats it as control flow rather than one more rule in the set.
"""

from __future__ import annotations

from opfor.core import Finding, World


def wildcards(world: World) -> list[Finding]:
    """Report the wildcard certificates the run saw as a named blind spot. A wildcard such as
    *.dev.example.com covers every host under it, so certificate transparency never names the
    individual hosts and passive discovery cannot see them. This is a fact about the reach of
    the run, not a semantic judgment, so it stays in code, and saying it keeps a silent gap
    from reading as a clean, complete result."""
    bases = sorted(n.payload.name for n in world.nodes("domain")
                   if getattr(n.payload, "wildcard", False))
    if not bases:
        return []
    shown = ", ".join(bases[:10]) + (f", and {len(bases) - 10} more" if len(bases) > 10 else "")
    return [Finding(
        id="finding:blindspot:wildcard",
        title=f"Wildcard certificate blind spot, {len(bases)} base(s) hide their subdomains",
        severity="INFO",
        where=shown,
        evidence=f"a wildcard certificate such as *.{bases[0]} covers every hostname under "
                 "it, so certificate transparency never names the individual hosts and "
                 "passive discovery cannot see them. Enumerate these bases from DNS or an "
                 "internal source to close the gap",
        data={"kind": "blindspot", "bases": bases},
    )]


def truncated(world: World) -> list[Finding]:
    """Report the roots whose passive enumeration hit a source page cap as a blind spot. A
    bounded walk that stopped short left subdomains unfetched, so the surface under these
    roots is incomplete. This is a fact about the reach of the run, not a semantic judgment,
    so it stays in code, and saying it keeps a truncated set from reading as a clean, complete
    result."""
    found = sorted(n.payload.name for n in world.nodes("domain")
                   if world.has_fact(n.id, "enumeration_truncated"))
    if not found:
        return []
    shown = ", ".join(found[:10]) + (f", and {len(found) - 10} more" if len(found) > 10 else "")
    return [Finding(
        id="finding:blindspot:enumeration",
        title=f"Passive enumeration truncated, {len(found)} root(s) hide subdomains beyond the page cap",
        severity="INFO",
        where=shown,
        evidence="a passive source returned more subdomains than the page cap fetched, so "
                 "the enumeration under these roots is incomplete. Raise the cap or "
                 "enumerate from DNS or an internal source to close the gap",
        data={"kind": "blindspot", "roots": found},
    )]


def coverage_gaps(world: World) -> list[Finding]:
    """Report each scan that finished but skipped items on per-item errors, an INFO line so a
    partial scan does not read as a clean negative. A fact about the reach of the run, not a
    semantic judgment, so it stays in code, and saying it keeps a dropped item from passing as
    covered, invariant 5."""
    out: list[Finding] = []
    for fact in world.facts("coverage_gap"):
        gap = fact.payload
        sample = "; ".join(gap.reasons)
        out.append(Finding(
            id=f"finding:coverage_gap:{gap.scan}:{gap.host}",
            title=f"{gap.scan} skipped {gap.failed} of {gap.attempted} item(s) on errors",
            severity="INFO",
            where=gap.host,
            evidence=f"{gap.failed} of {gap.attempted} items were skipped on fetch or "
                     f"probe errors, so the surface {gap.scan} reports for {gap.host} is "
                     f"partial rather than complete. Sample: {sample}. Rerun to cover the "
                     "skipped items",
            data={"kind": "coverage_gap", "scan": gap.scan, "failed": gap.failed,
                  "attempted": gap.attempted},
        ))
    return out


def resolution_caveat(world: World) -> Finding | None:
    """When almost nothing resolved the resolver is the problem, not the target, so probing and
    dangling results would be a wall of false positives. Above a high failure rate, say the run
    is incomplete rather than judging an unreachable surface. This trades a little recall for
    not lying, and it says so."""
    domains = world.nodes("domain")
    if not domains:
        return None
    unresolved = sum(
        1 for n in domains
        if not ((r := world.latest("resolved", n.id)) is not None and r.payload.resolvable)
    )
    if unresolved / len(domains) < 0.9:
        return None
    return Finding(
        id="finding:incomplete:resolution",
        title=f"Resolution unavailable, {unresolved} of {len(domains)} names did not resolve",
        severity="INFO",
        where="(resolver)",
        evidence="almost nothing resolved, so probing and dangling checks were suppressed "
                 "to avoid false positives, rerun from a host with a working resolver to "
                 "assess reachability",
        data={"kind": "incomplete", "unresolved": unresolved, "domains": len(domains)},
    )


# The inventory and coverage rules the judge runs unconditionally. Named here so the set of
# what triage mints outside the model is auditable in one place.
STRUCTURAL = (wildcards, truncated, coverage_gaps)

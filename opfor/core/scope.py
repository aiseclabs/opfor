"""The scope gate: deny-by-default authorization for every task.

Every task is authorized before it runs. A passive recon-tier lookup of a public
source is waved through as osint. Anything else must name a target that is in
scope, by host or by an opaque resource id, and must not exceed the campaign's tier
ceiling. The intrusive tier additionally requires an explicit, recorded
authorization, so the engine can run on its own yet only ever send a payload inside
a deliberate envelope a human declared. An unauthorized task fails loud, the loop
never silently proceeds.
"""

from __future__ import annotations

from dataclasses import dataclass

TIERS = ("recon", "probe", "intrusive")
_INTRUSIVE = TIERS.index("intrusive")


def tier_rank(tier: str) -> int:
    """Rank a tier, fail loud on an unknown one so a typo cannot widen scope."""
    if tier not in TIERS:
        raise ValueError(f"unknown tier {tier!r}, known: {', '.join(TIERS)}")
    return TIERS.index(tier)


@dataclass(frozen=True, kw_only=True)
class Decision:
    allowed: bool
    reason: str


class Scope:
    """Authorized hosts and resources, the tier ceiling, and the intrusive envelope.

    `osint` marks a capability as a passive read of a public source, so a recon-tier
    osint task needs no per-target authorization. Every other task is denied unless
    its target is in scope and its tier is within the ceiling.
    """

    def __init__(
        self,
        *,
        max_tier: str = "recon",
        hosts: tuple[str, ...] = (),
        resources: tuple[str, ...] = (),
        authorized: bool = False,
    ) -> None:
        tier_rank(max_tier)
        self.max_tier = max_tier
        self.hosts = tuple(hosts)
        self.resources = tuple(str(r).lower() for r in resources)
        self.authorized = authorized

    def authorize(self, tier: str, *, osint: bool, host: str | None = None,
                  resource: str | None = None) -> Decision:
        if osint and tier_rank(tier) == 0:
            return Decision(allowed=True, reason="passive osint")
        if resource is not None:
            if resource.lower() not in self.resources:
                return Decision(allowed=False, reason=f"resource out of scope: {resource!r}")
        elif host is not None:
            if not self._in_scope(host):
                return Decision(allowed=False, reason=f"host out of scope: {host!r}")
        else:
            return Decision(allowed=False, reason="task names no host or resource")
        if tier_rank(tier) > tier_rank(self.max_tier):
            return Decision(allowed=False, reason=f"tier {tier} exceeds ceiling {self.max_tier}")
        if tier_rank(tier) >= _INTRUSIVE and not self.authorized:
            return Decision(allowed=False, reason="intrusive tier requires explicit authorization")
        return Decision(allowed=True, reason="in scope")

    def _in_scope(self, host: str) -> bool:
        return any(host == h or host.endswith("." + h) for h in self.hosts)

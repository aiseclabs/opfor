"""The scope gate: deny-by-default authorization for every task.

Every task is authorized before it runs. A passive recon-tier lookup of a public source is
waved through as osint. Anything else must name a target the scenario's matcher places in
scope, and must not exceed the campaign's tier ceiling. The intrusive tier additionally
requires an explicit, recorded authorization, so the engine can run on its own yet only ever
send a payload inside a deliberate envelope a human declared. An unauthorized task fails loud,
the loop never silently proceeds.

The kernel judges the tier and the intrusive envelope, both generic. Whether a target is in
scope is the scenario's rule, since what a target even is, a host, an account, a person, is
scenario data, not engine knowledge. A scenario passes a `matcher`, and the kernel defaults to
exact-string membership, so a scenario whose targets are opaque ids wires no code and one whose
targets are hosts supplies its own suffix rule without the kernel ever naming a host.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Protocol, runtime_checkable

TIERS = ("recon", "intrusive")
_INTRUSIVE = TIERS.index("intrusive")


def tier_rank(tier: str) -> int:
    """Rank a tier, fail loud on an unknown one so a typo cannot widen scope."""
    if tier not in TIERS:
        raise ValueError(f"unknown tier {tier!r}, known: {', '.join(TIERS)}")
    return TIERS.index(tier)


@runtime_checkable
class ScopeMatcher(Protocol):
    """Decides whether a candidate target is in scope. A scenario implements the rule for its
    own target kind, and `to_dict` lets a checkpoint carry the rule's data across a resume."""

    def in_scope(self, target: str) -> bool: ...

    def to_dict(self) -> dict: ...


class ExactScope:
    """The kernel's default matcher: membership by exact, case and whitespace normalized
    string. A scenario whose targets are opaque ids needs nothing richer, and the kernel names
    no host by owning only this."""

    def __init__(self, targets: tuple[str, ...] = ()) -> None:
        self.targets = tuple(str(t).strip().lower() for t in targets)

    def in_scope(self, target: str) -> bool:
        return str(target).strip().lower() in self.targets

    def to_dict(self) -> dict:
        return {"targets": list(self.targets)}

    @classmethod
    def from_dict(cls, data: Mapping) -> "ExactScope":
        return cls(targets=tuple(data.get("targets", ())))


@dataclass(frozen=True, kw_only=True)
class Decision:
    allowed: bool
    reason: str


class Scope:
    """The tier ceiling, the intrusive envelope, and a scenario's in-scope matcher.

    `osint` marks a capability as a passive read of a public source, so a recon-tier osint task
    needs no per-target authorization. Every other task is denied unless its target is in scope
    by the matcher and its tier is within the ceiling.
    """

    def __init__(
        self,
        *,
        max_tier: str = "recon",
        matcher: ScopeMatcher | None = None,
        authorized: bool = False,
    ) -> None:
        tier_rank(max_tier)
        self.max_tier = max_tier
        # Default to exact membership over an empty set, so a scenario that authorizes purely by
        # osint, the mock reference for one, wires no matcher and every non-osint task is denied.
        self.matcher: ScopeMatcher = matcher if matcher is not None else ExactScope()
        self.authorized = authorized

    def authorize(self, tier: str, *, osint: bool, target: str | None = None) -> Decision:
        if osint and tier_rank(tier) == 0:
            return Decision(allowed=True, reason="passive osint")
        if target is None:
            return Decision(allowed=False, reason="task names no target")
        if not self.matcher.in_scope(target):
            return Decision(allowed=False, reason=f"target out of scope: {target!r}")
        if tier_rank(tier) > tier_rank(self.max_tier):
            return Decision(allowed=False, reason=f"tier {tier} exceeds ceiling {self.max_tier}")
        if tier_rank(tier) >= _INTRUSIVE and not self.authorized:
            return Decision(allowed=False, reason="intrusive tier requires explicit authorization")
        return Decision(allowed=True, reason="in scope")

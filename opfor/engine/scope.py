"""The scope gate. Deny-by-default authorization for every act.

Invariant 4: every act is authorized before it runs. Authorization has two
rungs in this skeleton, the first steps of the scope ladder. First, the target
host must be in the authorized set. Second, the action tier must not exceed the
campaign ceiling, so a campaign can permit recon while forbidding intrusive
acts. An unauthorized act fails loud, the loop never silently proceeds.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from opfor.engine.graph import SituationGraph
from opfor.model import Entrypoint

# Action tiers, least to most intrusive. A hand tags each action it offers via
# the entrypoint, so the tier stays data the hand declares, not engine logic.
TIERS = ("recon", "probe", "intrusive")


def tier_rank(tier: str) -> int:
    """Rank a tier, fail loud on an unknown tier so typos cannot widen scope."""
    if tier not in TIERS:
        raise ValueError(f"unknown action tier: {tier!r}, known: {TIERS}")
    return TIERS.index(tier)


@dataclass(frozen=True, kw_only=True)
class Decision:
    allowed: bool
    reason: str
    tier: str


class Scope:
    """Authorized hosts and domains plus the highest action tier permitted.

    A host passes when it matches an exact host, or when it is, or sits under,
    an authorized domain suffix. The suffix rung is what lets a recon campaign
    authorize a whole estate, every subdomain of an authorized root, without
    listing each host up front.
    """

    def __init__(
        self,
        *,
        hosts: tuple[str, ...] = (),
        domain_suffixes: tuple[str, ...] = (),
        max_tier: str,
    ) -> None:
        self.hosts = tuple(hosts)
        self.domain_suffixes = tuple(domain_suffixes)
        tier_rank(max_tier)  # validate eagerly
        self.max_tier = max_tier

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Scope":
        data = yaml.safe_load(Path(path).read_text()) or {}
        return cls(
            hosts=tuple(data.get("hosts", ())),
            domain_suffixes=tuple(data.get("domains", ())),
            max_tier=data.get("max_tier", "recon"),
        )

    def _action_tier(self, entrypoint: Entrypoint, action: str) -> str:
        """Read the tier the hand declared for this action.

        Default to the most intrusive tier when undeclared, so an unlabeled
        action is treated as dangerous rather than waved through.
        """
        tiers = entrypoint.props.get("action_tiers", {})
        return tiers.get(action, "intrusive")

    def _host_of(self, graph: SituationGraph, entrypoint: Entrypoint) -> str | None:
        """The host this act is aimed at.

        Prefer the host the hand stamped on the entrypoint, fall back to the
        owning target's host so the web and mock scenarios keep working.
        """
        stamped = entrypoint.props.get("scope_host")
        if stamped is not None:
            return stamped
        target = next(
            (t for t in graph.targets() if t.id == entrypoint.target_id), None
        )
        return target.props.get("host") if target is not None else None

    def _in_scope(self, host: str) -> bool:
        if host in self.hosts:
            return True
        return any(
            host == s or host.endswith("." + s) for s in self.domain_suffixes
        )

    def authorize(
        self, graph: SituationGraph, entrypoint: Entrypoint, action: str
    ) -> Decision:
        """Authorize one act. Deny unless both rungs pass."""
        tier = self._action_tier(entrypoint, action)
        # A passive OSINT lookup queries a public source about the target, it
        # never touches the estate, so it is not gated by the host scope. It must
        # still be a recon-tier action, so this cannot widen scope.
        if entrypoint.props.get("osint") and tier_rank(tier) == 0:
            return Decision(allowed=True, reason="passive osint", tier=tier)
        # A batch action carries many hosts. Every one must be in scope, and the
        # tier ceiling still applies, so a batch cannot smuggle past either rung.
        batch = entrypoint.props.get("scope_hosts")
        if batch is not None:
            out = [h for h in batch if not self._in_scope(h)]
            if out:
                return Decision(
                    allowed=False,
                    reason=f"{len(out)} hosts out of scope, e.g. {out[0]!r}",
                    tier=tier,
                )
            if tier_rank(tier) > tier_rank(self.max_tier):
                return Decision(
                    allowed=False,
                    reason=f"tier {tier} exceeds ceiling {self.max_tier}",
                    tier=tier,
                )
            return Decision(allowed=True, reason="batch in scope", tier=tier)
        host = self._host_of(graph, entrypoint)
        if host is None:
            return Decision(
                allowed=False,
                reason=f"no host for entrypoint {entrypoint.id}",
                tier=tier,
            )
        if not self._in_scope(host):
            return Decision(
                allowed=False,
                reason=f"host out of scope: {host!r}",
                tier=tier,
            )
        if tier_rank(tier) > tier_rank(self.max_tier):
            return Decision(
                allowed=False,
                reason=f"tier {tier} exceeds ceiling {self.max_tier}",
                tier=tier,
            )
        return Decision(allowed=True, reason="in scope", tier=tier)

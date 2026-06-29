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

# Action tiers, least to most intrusive. A task declares its own tier, so the
# tier stays data the planner sets, not engine logic.
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

    def _in_scope(self, host: str) -> bool:
        if host in self.hosts:
            return True
        return any(
            host == s or host.endswith("." + s) for s in self.domain_suffixes
        )

    def authorize_task(self, graph: SituationGraph, task) -> Decision:
        """Authorize one task. Same rungs as authorize, on the task's own fields.

        A passive OSINT task (recon tier, not touching the estate) is allowed.
        Otherwise the task's scope_host must be in scope and its tier within the
        ceiling. Deny-by-default.
        """
        tier = task.tier
        if task.osint and tier_rank(tier) == 0:
            return Decision(allowed=True, reason="passive osint", tier=tier)
        host = task.scope_host
        if host is None:
            return Decision(allowed=False, reason=f"no host for task {task.id}", tier=tier)
        if not self._in_scope(host):
            return Decision(allowed=False, reason=f"host out of scope: {host!r}", tier=tier)
        if tier_rank(tier) > tier_rank(self.max_tier):
            return Decision(
                allowed=False, reason=f"tier {tier} exceeds ceiling {self.max_tier}", tier=tier
            )
        return Decision(allowed=True, reason="in scope", tier=tier)

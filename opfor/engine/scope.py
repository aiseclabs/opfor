"""The scope gate. Deny-by-default authorization for every act.

Invariant 4: every task is authorized before it runs. Three rungs, deny-by-default:
1. The target host must be in the authorized set (exact host or under a domain
   suffix), unless it is a passive recon-tier OSINT lookup of a public source.
2. The task tier must not exceed the campaign ceiling (max_tier).
3. Intrusive tier (payload-sending) additionally requires an explicit, recorded
   authorization in the campaign. This is the authorization envelope: opfor can
   run fully autonomously, but it only ever sends payloads inside a deliberate,
   audited authorization that a human declared in the campaign, never by accident.
An unauthorized task fails loud, the loop never silently proceeds.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from opfor.engine.graph import SituationGraph

# Action tiers, least to most intrusive. A task declares its own tier, so the
# tier stays data the planner sets, not engine logic.
TIERS = ("recon", "probe", "intrusive")
_INTRUSIVE = TIERS.index("intrusive")


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
    """Authorized hosts and domains, the tier ceiling, and the authorization envelope.

    A host passes when it matches an exact host, or sits under an authorized
    domain suffix. Intrusive tier additionally requires `authorized` to be true,
    set either directly (in code) or from the campaign's `authorization` block.
    """

    def __init__(
        self,
        *,
        hosts: tuple[str, ...] = (),
        domain_suffixes: tuple[str, ...] = (),
        max_tier: str,
        authorized: bool = False,
        authorization: dict | None = None,
    ) -> None:
        self.hosts = tuple(hosts)
        self.domain_suffixes = tuple(domain_suffixes)
        tier_rank(max_tier)  # validate eagerly
        self.max_tier = max_tier
        self.authorization = authorization
        self.authorized = bool(authorized or (authorization and authorization.get("authorized")))

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Scope":
        data = yaml.safe_load(Path(path).read_text()) or {}
        max_tier = data.get("max_tier", "recon")
        authorization = data.get("authorization")
        authorized = bool(authorization and authorization.get("authorized"))
        # Fail loud: an intrusive campaign must carry an explicit authorization
        # block, so payload-sending is never enabled by a stray `max_tier` line.
        if tier_rank(max_tier) >= _INTRUSIVE and not authorized:
            raise ValueError(
                f"scope at {path}: max_tier '{max_tier}' is intrusive and requires an "
                "`authorization:` block with `authorized: true` (and a reference/note)"
            )
        return cls(
            hosts=tuple(data.get("hosts", ())),
            domain_suffixes=tuple(data.get("domains", ())),
            max_tier=max_tier,
            authorization=authorization,
        )

    @property
    def authorization_ref(self) -> str:
        if not self.authorization:
            return ""
        return str(self.authorization.get("reference") or self.authorization.get("note") or "")

    def _in_scope(self, host: str) -> bool:
        if host in self.hosts:
            return True
        return any(
            host == s or host.endswith("." + s) for s in self.domain_suffixes
        )

    def authorize_task(self, graph: SituationGraph, task) -> Decision:
        """Authorize one task. Deny-by-default across all three rungs."""
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
        if tier_rank(tier) >= _INTRUSIVE and not self.authorized:
            return Decision(
                allowed=False,
                reason="intrusive tier requires explicit campaign authorization",
                tier=tier,
            )
        return Decision(allowed=True, reason="in scope", tier=tier)

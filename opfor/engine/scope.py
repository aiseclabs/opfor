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
    """Authorized hosts plus the highest action tier the campaign permits."""

    def __init__(self, *, hosts: tuple[str, ...], max_tier: str) -> None:
        self.hosts = tuple(hosts)
        tier_rank(max_tier)  # validate eagerly
        self.max_tier = max_tier

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Scope":
        data = yaml.safe_load(Path(path).read_text()) or {}
        return cls(
            hosts=tuple(data.get("hosts", ())),
            max_tier=data.get("max_tier", "recon"),
        )

    def _action_tier(self, entrypoint: Entrypoint, action: str) -> str:
        """Read the tier the hand declared for this action.

        Default to the most intrusive tier when undeclared, so an unlabeled
        action is treated as dangerous rather than waved through.
        """
        tiers = entrypoint.props.get("action_tiers", {})
        return tiers.get(action, "intrusive")

    def authorize(
        self, graph: SituationGraph, entrypoint: Entrypoint, action: str
    ) -> Decision:
        """Authorize one act. Deny unless both rungs pass."""
        tier = self._action_tier(entrypoint, action)
        target = next(
            (t for t in graph.targets() if t.id == entrypoint.target_id), None
        )
        if target is None:
            return Decision(
                allowed=False,
                reason=f"no target for entrypoint {entrypoint.id}",
                tier=tier,
            )
        host = target.props.get("host")
        if host not in self.hosts:
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

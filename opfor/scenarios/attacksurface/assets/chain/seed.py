"""The scenario seed type, the one payload the asset class reads.

The seed is a `Survey`, a chain to sweep and the activity floor that bounds the sweep. By default
the run discovers contracts by sweeping the active DEX pools and pivoting to the fund contracts
behind each token or pool. The operator may instead name `anchors`, explicit contract addresses to
audit directly, for a focused run that skips the sweep. Only the seed lives here, since the class
reads it.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, kw_only=True)
class Survey:
    """The seed: a chain, the sweep floor, and optional explicit anchors. `name` is the operator's
    label. `chain` is the chain id the DEX and explorer seams speak, bsc to start. The floor bounds
    the sweep, `min_liquidity` and `min_volume` in USD and `age_days` the maximum pool age, None for
    no age bound. `anchors` are contract addresses the operator wants audited directly, and when any
    are given the sweep is skipped, the run enriches and judges exactly those and what they pivot
    to."""

    name: str
    chain: str = "ethereum"
    min_liquidity: float = 50_000.0
    min_volume: float = 5_000.0
    age_days: float | None = 90.0
    # The discovery age band in days. The floor skips the just-launched churn that has no fund
    # contract or source yet, the ceiling skips the established bluechips that have had years of
    # audits, so the sweep lands on the young-but-real projects that are the audit sweet spot.
    min_age_days: float = 2.0
    max_age_days: float = 45.0
    anchors: tuple[str, ...] = field(default_factory=tuple)

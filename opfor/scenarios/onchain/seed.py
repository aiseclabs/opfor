"""The scenario seed type, the one payload the asset class reads.

The seed is a `Survey`, a chain to sweep and the activity floor that bounds the sweep. The
run does not take contract addresses from the operator, it discovers them by sweeping the
active DEX pools and pivoting to the fund contracts behind each token or pool. Only the seed
lives here, since the class reads it.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, kw_only=True)
class Survey:
    """The seed: a chain and the sweep floor. `name` is the operator's label for the run.
    `chain` is the chain id the DEX and explorer seams speak, bsc to start. The floor bounds
    the sweep so it reads the active surface, not the whole chain, `min_liquidity` and
    `min_volume` in USD and `age_days` the maximum pool age, None for no age bound."""

    name: str
    chain: str = "bsc"
    min_liquidity: float = 10_000.0
    min_volume: float = 5_000.0
    age_days: float | None = 90.0

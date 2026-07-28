"""The typed observations the source seams return, so a capability reads typed attributes.

A seam is the injected boundary to a public source, the DEX index, the block explorer, and the
RPC. It returns one of these frozen dataclasses, never a loose dict, so the capability that
turns an observation into facts reads a typed field and a test builds a fixture by name. This
mirrors the domain class's `observations`, the same decoupling.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, kw_only=True)
class PoolObservation:
    """One active DEX pool the sweep saw. Roles ride provisional, the pool address is a `pool`
    and its two tokens are `token` nodes. `liquidity_usd` and `volume_24h` are the activity the
    floor filtered on, `age_days` the pool age or None when the source did not carry it."""

    address: str
    chain: str
    dex_id: str = ""
    url: str = ""
    base_address: str = ""
    base_symbol: str = ""
    quote_address: str = ""
    quote_symbol: str = ""
    liquidity_usd: float = 0.0
    volume_24h: float = 0.0
    age_days: float | None = None


@dataclass(frozen=True, kw_only=True)
class RelatedObservation:
    """A contract found behind a token or pool, the pivot's output. `role_hint` is what the pivot
    inferred, `unknown` when it only found an address, and `via` names how it was found so a
    reader can weigh it."""

    address: str
    chain: str
    role_hint: str = "unknown"
    via: str = ""


@dataclass(frozen=True, kw_only=True)
class SourceObservation:
    """The explorer's answer for one address. `verified` is whether verified source was served,
    `functions` the external and public function names read from the ABI, `source_text` the
    verified source, and `note` why source was missing when it was."""

    verified: bool = False
    functions: tuple[str, ...] = ()
    source_text: str = ""
    note: str = ""


@dataclass(frozen=True, kw_only=True)
class FundObservation:
    """The funds read for one address. `funds_at_risk_usd` is the conservative figure, `assets`
    the kinds counted, and `note` the confidence and any balance the seam could not read."""

    funds_at_risk_usd: float = 0.0
    assets: tuple[str, ...] = ()
    note: str = ""

"""The DEX Screener source seam, token pricing and the shallow pivot over its public index.

The sweep reads the active pools for a chain from DEX Screener, bounded by the survey's activity
floor. The pivot, from a token or pool, finds the other pools that reference the same token, the
shallow first hop. A deeper pivot, following contract holders and transfer history to the staking
or vault behind a token, needs a keyed explorer and is the tracked next increment, so this seam
finds the pools honestly and notes what it did not walk. A test injects its own seam, so this
default is the live wiring, not a dependency of the class's logic.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request

from opfor.scenarios.onchain.assets.contract.sources.observations import (
    PoolObservation,
    RelatedObservation,
)

_DEXSCREENER = "https://api.dexscreener.com"
_TIMEOUT = 15.0
_DEFAULT_TERMS = ("WETH USDC", "WETH USDT", "ETH DAI", "new pair")
# Cap the swept pools so a broad chain sweep does not fan out into an ENRICH the budget cannot
# finish. The richest pools by liquidity are kept, the tail is dropped, and a bounded run closes.
_MAX_POOLS = 15
# The shallow pivot can return dozens of pools for one token, which floods MAP and exhausts the
# budget before ENRICH runs. Cap the breadth so a single hop stays bounded. The pools are ranked
# by liquidity so the cap keeps the richest, and a deeper pivot to the fund contracts behind a
# token, the real value, is the tracked next increment.
_MAX_RELATED = 8


def _get_json(url: str):
    request = urllib.request.Request(url, headers={"User-Agent": "opfor-onchain/0.1"})
    with urllib.request.urlopen(request, timeout=_TIMEOUT) as response:
        return json.loads(response.read().decode("utf-8"))


def _pool_from_pair(pair: dict) -> PoolObservation | None:
    address = pair.get("pairAddress")
    base = pair.get("baseToken") or {}
    quote = pair.get("quoteToken") or {}
    if not address or not base.get("address") or not quote.get("address"):
        return None
    return PoolObservation(
        address=address, chain=pair.get("chainId") or "", dex_id=pair.get("dexId") or "",
        url=pair.get("url") or "", base_address=base.get("address") or "",
        base_symbol=base.get("symbol") or "", quote_address=quote.get("address") or "",
        quote_symbol=quote.get("symbol") or "",
        liquidity_usd=float((pair.get("liquidity") or {}).get("usd") or 0),
        volume_24h=float((pair.get("volume") or {}).get("h24") or 0))


def sweep(survey) -> tuple[PoolObservation, ...]:
    """Read the active pools for the survey's chain, filtered by its liquidity and volume floor."""
    seen: dict[str, PoolObservation] = {}
    for term in _DEFAULT_TERMS:
        query = urllib.parse.urlencode({"q": term})
        data = _get_json(f"{_DEXSCREENER}/latest/dex/search?{query}")
        for pair in data.get("pairs") or []:
            if pair.get("chainId") != survey.chain:
                continue
            pool = _pool_from_pair(pair)
            if pool is None:
                continue
            if pool.liquidity_usd < survey.min_liquidity or pool.volume_24h < survey.min_volume:
                continue
            seen[pool.address.lower()] = pool
    ranked = sorted(seen.values(), key=lambda p: p.liquidity_usd, reverse=True)
    return tuple(ranked[:_MAX_POOLS])


def token_price_usd(address: str, chain: str) -> float | None:
    """The USD price of a token, read from its deepest DEX pool. None when no priced pool is seen,
    so the funds read counts what it can price and no more."""
    data = _get_json(f"{_DEXSCREENER}/latest/dex/tokens/{address}")
    best: tuple[float, float] | None = None
    for pair in data.get("pairs") or []:
        if pair.get("chainId") != chain:
            continue
        price = pair.get("priceUsd")
        liquidity = float((pair.get("liquidity") or {}).get("usd") or 0)
        if price and (best is None or liquidity > best[1]):
            best = (float(price), liquidity)
    return best[0] if best is not None else None


def pivot(contract) -> tuple[RelatedObservation, ...]:
    """Find the pools that reference this token, the shallow first hop. For a token it queries the
    token's pairs, for a pool it does nothing, the pool is already the leaf a token pointed at."""
    if contract.role != "token":
        return ()
    data = _get_json(f"{_DEXSCREENER}/token-pairs/v1/{contract.chain}/{contract.address}")
    pairs = data if isinstance(data, list) else (data.get("pairs") or [])
    ranked = sorted(pairs, key=lambda p: float((p.get("liquidity") or {}).get("usd") or 0),
                    reverse=True)
    related: dict[str, RelatedObservation] = {}
    for pair in ranked:
        address = pair.get("pairAddress")
        if address and address.lower() != contract.address.lower():
            related[address.lower()] = RelatedObservation(
                address=address, chain=contract.chain, role_hint="pool",
                via="dexscreener token-pairs")
        if len(related) >= _MAX_RELATED:
            break
    return tuple(related.values())

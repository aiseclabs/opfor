"""The DEX source seam, the default sweep and pivot over public DEX indexes.

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
_DEFAULT_TERMS = ("WBNB USDT", "BSC USDC", "CAKE WBNB", "BSC new pair")


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
    return tuple(seen.values())


def pivot(contract) -> tuple[RelatedObservation, ...]:
    """Find the pools that reference this token, the shallow first hop. For a token it queries the
    token's pairs, for a pool it does nothing, the pool is already the leaf a token pointed at."""
    if contract.role != "token":
        return ()
    data = _get_json(f"{_DEXSCREENER}/token-pairs/v1/{contract.chain}/{contract.address}")
    pairs = data if isinstance(data, list) else (data.get("pairs") or [])
    related: dict[str, RelatedObservation] = {}
    for pair in pairs:
        address = pair.get("pairAddress")
        if address and address.lower() != contract.address.lower():
            related[address.lower()] = RelatedObservation(
                address=address, chain=contract.chain, role_hint="pool",
                via="dexscreener token-pairs")
    return tuple(related.values())

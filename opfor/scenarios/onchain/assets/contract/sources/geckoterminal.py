"""The new-pool discovery seam, the default sweep over recently created pools.

The mission is the long tail, small, new, unaudited contracts that hold enough funds to matter, not
the established bluechips a size-ranked sweep would surface first. So the sweep reads a chain's
recently created pools from GeckoTerminal, newest first, and keeps the ones that already hold real
liquidity, a floor so there are funds to lose but no ceiling that would exclude a large new project.
It carries the pool age, so a downstream step can weigh novelty. A test injects its own seam.
"""

from __future__ import annotations

import json
import urllib.request
from datetime import datetime, timezone

from opfor.scenarios.onchain.assets.contract.sources.observations import PoolObservation

_BASE = "https://api.geckoterminal.com/api/v2"
_TIMEOUT = 15.0
# The GeckoTerminal network id per chain, distinct from the DexScreener and Etherscan chain names.
_NETWORK = {"ethereum": "eth", "bsc": "bsc"}
# How many recent pools to read across pages, and the cap on what a sweep hands to ENRICH so a
# broad discovery does not fan out past the budget.
_PAGES = 2
_MAX_POOLS = 5


def _get(url: str):
    request = urllib.request.Request(url, headers={"User-Agent": "opfor-onchain/0.1"})
    with urllib.request.urlopen(request, timeout=_TIMEOUT) as response:
        return json.loads(response.read().decode("utf-8"))


def _relationship_address(relationships: dict, key: str) -> str:
    token_id = (((relationships.get(key) or {}).get("data") or {}).get("id") or "")
    return token_id.split("_", 1)[1] if "_" in token_id else token_id


def _symbols(name: str) -> tuple[str, str]:
    if "/" not in name:
        return name.strip() or "UNKNOWN", "UNKNOWN"
    base, _, rest = name.partition("/")
    return base.strip() or "UNKNOWN", rest.strip().split(" ", 1)[0] or "UNKNOWN"


def _age_days(created: str | None) -> float | None:
    if not created:
        return None
    try:
        when = datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError:
        return None
    return max(0.0, (datetime.now(timezone.utc) - when).total_seconds() / 86400)


def _parse(item: dict, chain: str) -> PoolObservation | None:
    attributes = item.get("attributes") or {}
    relationships = item.get("relationships") or {}
    address = attributes.get("address")
    if not address:
        return None
    base_symbol, quote_symbol = _symbols(attributes.get("name") or "")
    return PoolObservation(
        address=address, chain=chain,
        dex_id=(((relationships.get("dex") or {}).get("data") or {}).get("id") or ""),
        url=f"https://www.geckoterminal.com/{_NETWORK.get(chain, chain)}/pools/{address}",
        base_address=_relationship_address(relationships, "base_token"),
        base_symbol=base_symbol,
        quote_address=_relationship_address(relationships, "quote_token"),
        quote_symbol=quote_symbol,
        liquidity_usd=float(attributes.get("reserve_in_usd") or 0),
        volume_24h=float((attributes.get("volume_usd") or {}).get("h24") or 0),
        age_days=_age_days(attributes.get("pool_created_at")))


def new_pools(survey) -> tuple[PoolObservation, ...]:
    """Read the chain's recently created pools, newest first, keeping those that clear the liquidity
    floor so there are real funds behind them. Volume is not floored, since a brand-new pool has not
    yet built a day of it."""
    network = _NETWORK.get(survey.chain)
    if network is None:
        return ()
    seen: dict[str, PoolObservation] = {}
    for page in range(1, _PAGES + 1):
        data = _get(f"{_BASE}/networks/{network}/new_pools?page={page}")
        for item in data.get("data") or []:
            pool = _parse(item, survey.chain)
            if pool is not None and pool.liquidity_usd >= survey.min_liquidity:
                seen.setdefault(pool.address.lower(), pool)
    return tuple(list(seen.values())[:_MAX_POOLS])

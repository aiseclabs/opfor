"""The discovery seam, the default sweep over a chain's young-but-real pools.

The mission is the long tail, projects deployed days to weeks ago that hold real funds, not the
just-launched churn with no fund contract or verified source yet, and not the established
bluechips that have had years of audits. So the sweep reads both the recently created pools and
the trending pools, then keeps those inside an age band, the floor skipping the too-fresh, the
ceiling skipping the bluechips, above a liquidity floor so there are funds behind them. It carries
the pool age so a downstream step can weigh novelty. A test injects its own seam.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

from opfor.scenarios.onchain.assets.contract.chains import default_chain_policy
from opfor.scenarios.onchain.assets.contract.sources.observations import PoolObservation
from opfor.core import env_float, env_int

_BASE = "https://api.geckoterminal.com/api/v2"
_TIMEOUT = 15.0
# The keyless GeckoTerminal free tier caps calls at about thirty a minute and answers an over-cap
# request with a hard 429, which without pacing fails the whole sweep and yields no pools. So the
# same two defenses as the explorer: a process-wide throttle keeps the discovery under the cap, and
# a 429 that slips through is backed off and retried before it fails loud. The interval is generous
# by default since a broad sweep reads several pages. `OPFOR_GECKOTERMINAL_MIN_INTERVAL` tunes it.
_MIN_INTERVAL_DEFAULT = 2.1
_RETRIES = 4
_BACKOFF = 5.0
_THROTTLE_LOCK = threading.Lock()
_next_call = [0.0]


def _min_interval() -> float:
    """The minimum seconds between calls. A set-but-unparsable value fails loud, invariant 5."""
    return env_float("OPFOR_GECKOTERMINAL_MIN_INTERVAL", _MIN_INTERVAL_DEFAULT, minimum=0.0)


def _throttle(interval: float) -> None:
    """Block until at least `interval` seconds have passed since the last call, across threads."""
    if interval <= 0:
        return
    with _THROTTLE_LOCK:
        now = time.monotonic()
        wait = _next_call[0] - now
        if wait > 0:
            time.sleep(wait)
        _next_call[0] = time.monotonic() + interval
# The GeckoTerminal network id per chain lives in the chain policy, `knowledge/chains.yaml`,
# distinct from the DexScreener and Etherscan chain names. A new chain is one data edit there.


def _network(chain: str) -> str | None:
    return default_chain_policy().gecko_network(chain)
# How many recent pools to read across pages, and the cap on what a sweep hands to ENRICH so a
# broad discovery does not fan out past the budget. Both default small, precision over breadth, and
# both are env-tunable so an operator can widen the sweep to accumulate more of the long tail when
# breadth is what they want, at the cost of pulling in weaker, lower-liquidity candidates.
_PAGES_DEFAULT = 2
_MAX_POOLS_DEFAULT = 5


def _pages() -> int:
    """The pages of each discovery feed to read, `OPFOR_ONCHAIN_DISCOVERY_PAGES` or the default. A
    set-but-unparsable value fails loud rather than silently using the default, invariant 5."""
    return env_int("OPFOR_ONCHAIN_DISCOVERY_PAGES", _PAGES_DEFAULT, minimum=1)


def _max_pools() -> int:
    """The cap on pools a sweep hands to ENRICH, `OPFOR_ONCHAIN_MAX_POOLS` or the default. A
    set-but-unparsable value fails loud rather than silently using the default, invariant 5."""
    return env_int("OPFOR_ONCHAIN_MAX_POOLS", _MAX_POOLS_DEFAULT, minimum=1)


def _get(url: str):
    request = urllib.request.Request(url, headers={"User-Agent": "opfor-onchain/0.1"})
    interval = _min_interval()
    for attempt in range(_RETRIES):
        _throttle(interval)
        try:
            with urllib.request.urlopen(request, timeout=_TIMEOUT) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 429 and attempt < _RETRIES - 1:
                time.sleep(_BACKOFF * (attempt + 1))
                continue
            raise


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
        url=f"https://www.geckoterminal.com/{_network(chain) or chain}/pools/{address}",
        base_address=_relationship_address(relationships, "base_token"),
        base_symbol=base_symbol,
        quote_address=_relationship_address(relationships, "quote_token"),
        quote_symbol=quote_symbol,
        liquidity_usd=float(attributes.get("reserve_in_usd") or 0),
        volume_24h=float((attributes.get("volume_usd") or {}).get("h24") or 0),
        age_days=_age_days(attributes.get("pool_created_at")))


def select(pools, survey, cap=None) -> tuple[PoolObservation, ...]:
    """Keep the pools inside the survey's age band and above its liquidity floor, deduped and
    capped, richest first. Pure, so the band logic is tested without the network. A pool with an
    unknown age is dropped, since the band is the point of this discovery. The cap defaults to the
    env-tuned pool ceiling, a caller passes its own to test the capping deterministically."""
    ceiling = _max_pools() if cap is None else cap
    seen: dict[str, PoolObservation] = {}
    for pool in pools:
        if pool is None or pool.liquidity_usd < survey.min_liquidity:
            continue
        if pool.age_days is None or not survey.min_age_days <= pool.age_days <= survey.max_age_days:
            continue
        seen.setdefault(pool.address.lower(), pool)
    ranked = sorted(seen.values(), key=lambda p: p.liquidity_usd, reverse=True)
    return tuple(ranked[:ceiling])


def discover(survey) -> tuple[PoolObservation, ...]:
    """Read the chain's trending and recently created pools and keep the young-but-real ones. The
    two feeds together cover the band, trending surfaces the projects with traction and new_pools
    the fresher ones, and `select` keeps only those the age band and liquidity floor admit."""
    network = _network(survey.chain)
    if network is None:
        return ()
    raw: list = []
    for feed in ("pools", "new_pools"):
        for page in range(1, _pages() + 1):
            data = _get(f"{_BASE}/networks/{network}/{feed}?page={page}")
            raw.extend(_parse(item, survey.chain) for item in data.get("data") or [])
    return select(raw, survey)

"""The explorer transport, one place that speaks the Etherscan V2 multichain API.

Etherscan unified its per-chain explorers, BscScan among them, behind one V2 endpoint keyed by a
`chainid`, so a single key reads every supported chain. The source read and the transfer read both
go through here, so the key name, the chain-id map, and the request shape live in one module. It
needs a key, from `OPFOR_ETHERSCAN_API_KEY`, so a caller checks `configured` and degrades to its
keyless mode rather than firing a request that would only return a key error.
"""

from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request

_API = "https://api.etherscan.io/v2/api"
_TIMEOUT = 15.0
# The free tier caps calls per second, and a throttled reply comes back as an HTTP 200 whose body
# says so, not as an error. Back off and retry a few times, then fail loud, so a throttled read is
# never mistaken for an unverified contract or an empty result, invariant 5.
_MAX_RETRIES = 5
_BACKOFF = 0.6
# The V2 chain id per chain the scenario speaks. Ethereum is the primary chain, its free tier has
# full module access, source, transfers, and the proxy RPC. A non-Ethereum chain such as bsc reads
# verified source on the free tier but not the account and logs modules the deep pivot needs, so it
# needs a paid plan. A new chain is one entry here, not a code change.
_CHAIN_ID = {"ethereum": 1, "bsc": 56}


def api_key() -> str | None:
    """The explorer key. `OPFOR_ETHERSCAN_API_KEY` is the name, `OPFOR_EXPLORER_KEY` is accepted as
    an older alias so an existing environment keeps working."""
    return os.environ.get("OPFOR_ETHERSCAN_API_KEY") or os.environ.get("OPFOR_EXPLORER_KEY")


def chain_id(chain: str) -> int | None:
    return _CHAIN_ID.get(chain)


def configured(chain: str) -> bool:
    """Whether a request can be made, the chain is mapped and a key is set. A caller checks this
    and degrades cleanly rather than firing a request that can only fail."""
    return chain_id(chain) is not None and bool(api_key())


def _rate_limited(data) -> bool:
    """Whether a 200-body is a throttle notice rather than an answer. A genuine unverified-source
    reply also carries status 0, so this matches only the rate-limit wording, not every NOTOK."""
    text = f"{data.get('message', '')} {data.get('result', '')}".lower()
    if "rate limit" in text or "max calls" in text:
        return True
    error = data.get("error")
    return isinstance(error, dict) and "rate limit" in str(error.get("message", "")).lower()


def get(chain: str, params: dict):
    """Make one V2 call for a chain and return the parsed json. Assumes `configured`, so a caller
    checks first. Backs off and retries a throttled reply, then raises so a persistent throttle
    fails loud rather than reading as an empty or unverified result. Raises on a network error too,
    which the calling capability turns into a loud failure."""
    query = urllib.parse.urlencode({"chainid": chain_id(chain), **params, "apikey": api_key()})
    request = urllib.request.Request(f"{_API}?{query}", headers={"User-Agent": "opfor-onchain/0.1"})
    for attempt in range(_MAX_RETRIES):
        with urllib.request.urlopen(request, timeout=_TIMEOUT) as response:
            data = json.loads(response.read().decode("utf-8"))
        if not _rate_limited(data):
            return data
        time.sleep(_BACKOFF * (attempt + 1))
    raise RuntimeError("etherscan rate limit persisted after retries")


def proxy(chain: str, action: str, params: dict):
    """One `proxy` module call, the explorer's JSON-RPC pass-through, and return the raw `result`.
    This is how the RPC reads reach the chain over the one reachable host and the one key, rather
    than a separate node endpoint. Returns None when not configured, so a caller degrades cleanly."""
    if not configured(chain):
        return None
    return get(chain, {"module": "proxy", "action": action, **params}).get("result")

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
import threading
import time
import urllib.parse
import urllib.request

from opfor.scenarios.onchain.assets.contract.chains import default_chain_policy
from opfor.scenarios.onchain.env import env_float

_API = "https://api.etherscan.io/v2/api"
_TIMEOUT = 15.0
# The free tier caps calls per second, and a throttled reply comes back as an HTTP 200 whose body
# says so, not as an error. Two defenses stack. First a process-wide throttle paces every call so a
# burst of balance reads, one contract's funds read alone fires several, stays under the cap rather
# than tripping it, see `_etherscan_wait`. Second, a reply that is throttled anyway is backed off
# and retried a few times, then fails loud, so a throttled read is never mistaken for an unverified
# contract or an empty result, invariant 5.
_MAX_RETRIES = 5
_BACKOFF = 0.6
# The minimum seconds between calls, so the run holds under the free 5 per second cap with margin.
# One contract's funds read fires a balanceOf per value token plus native and decimals, so without
# pacing a single read bursts past the cap. `OPFOR_ETHERSCAN_MIN_INTERVAL` tunes it, 0 disables it
# for a paid plan. The throttle is process-wide so it holds even if reads ever run concurrently.
_MIN_INTERVAL_DEFAULT = 0.22
_THROTTLE_LOCK = threading.Lock()
_next_call = [0.0]


def _min_interval() -> float:
    """The configured minimum seconds between calls, read at the call so a changed environment is
    seen. A set-but-unparsable value fails loud rather than silently using the default, invariant 5."""
    return env_float("OPFOR_ETHERSCAN_MIN_INTERVAL", _MIN_INTERVAL_DEFAULT, minimum=0.0)


def _etherscan_wait(interval: float) -> None:
    """Block until at least `interval` seconds have passed since the last call, across all threads,
    so a burst of reads does not blow the per-second cap. A zero interval is a no-op."""
    if interval <= 0:
        return
    with _THROTTLE_LOCK:
        now = time.monotonic()
        wait = _next_call[0] - now
        if wait > 0:
            time.sleep(wait)
        _next_call[0] = time.monotonic() + interval
# The V2 chain id per chain the scenario speaks. Ethereum is the primary chain, its free tier has
# full module access, source, transfers, and the proxy RPC. A non-Ethereum chain such as bsc reads
# verified source on the free tier but not the account and logs modules the deep pivot needs, so it
# needs a paid plan. The per-chain id lives in the chain policy, `knowledge/chains.yaml`, so a new
# chain is one data edit there, not a code change here.


def api_key() -> str | None:
    """The explorer key. `OPFOR_ETHERSCAN_API_KEY` is the name, `OPFOR_EXPLORER_KEY` is accepted as
    an older alias so an existing environment keeps working."""
    return os.environ.get("OPFOR_ETHERSCAN_API_KEY") or os.environ.get("OPFOR_EXPLORER_KEY")


def chain_id(chain: str) -> int | None:
    return default_chain_policy().chain_id(chain)


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


class AccessDenied(RuntimeError):
    """The explorer denies free-tier access to a module on this chain. A distinct type so a caller
    that can degrade, the deep pivot dropping to shallow, catches exactly this and not a transient
    error, while a caller that must not guess, the funds read, lets it propagate and fail loud."""


def _access_denied(data) -> bool:
    """Whether a 200-body is a plan or access denial for the chain rather than an answer. The free
    tier answers a gated chain's account or proxy module with status 0 and this wording. A caller
    would read that error string as a codeless address or a zero balance, silently wrong, so it must
    be caught and failed loud, invariant 5. The phrasing never appears in a legitimate result, so
    matching it does not swallow a real answer such as an unverified-source reply."""
    text = f"{data.get('message', '')} {data.get('result', '')}".lower()
    return "not supported for this chain" in text or "upgrade your api plan" in text


def get(chain: str, params: dict):
    """Make one V2 call for a chain and return the parsed json. Assumes `configured`, so a caller
    checks first. Backs off and retries a throttled reply, then raises so a persistent throttle
    fails loud rather than reading as an empty or unverified result. Raises on a network error too,
    which the calling capability turns into a loud failure."""
    query = urllib.parse.urlencode({"chainid": chain_id(chain), **params, "apikey": api_key()})
    request = urllib.request.Request(f"{_API}?{query}", headers={"User-Agent": "opfor-onchain/0.1"})
    interval = _min_interval()
    for attempt in range(_MAX_RETRIES):
        _etherscan_wait(interval)
        with urllib.request.urlopen(request, timeout=_TIMEOUT) as response:
            data = json.loads(response.read().decode("utf-8"))
        # A plan denial for the chain is terminal, retrying does not lift it, so fail loud at once
        # rather than reading the error string as a codeless address or a zero balance.
        if _access_denied(data):
            module = params.get("module") or params.get("action") or "this module"
            raise AccessDenied(
                f"etherscan denies free-tier access to {module} on {chain}, upgrade the plan or use "
                f"a chain the key covers: {data.get('result') or data.get('message')}")
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

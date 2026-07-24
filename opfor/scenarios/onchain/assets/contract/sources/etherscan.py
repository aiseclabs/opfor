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
import urllib.parse
import urllib.request

_API = "https://api.etherscan.io/v2/api"
_TIMEOUT = 15.0
# The V2 chain id per chain the scenario speaks. A second chain is one entry, not a code change.
_CHAIN_ID = {"bsc": 56}


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


def get(chain: str, params: dict):
    """Make one V2 call for a chain and return the parsed json. Assumes `configured`, so a caller
    checks first. Raises on a network error, which the calling capability turns into a loud
    failure."""
    query = urllib.parse.urlencode({"chainid": chain_id(chain), **params, "apikey": api_key()})
    request = urllib.request.Request(f"{_API}?{query}", headers={"User-Agent": "opfor-onchain/0.1"})
    with urllib.request.urlopen(request, timeout=_TIMEOUT) as response:
        return json.loads(response.read().decode("utf-8"))

"""The funds source seam, the default read of the value a contract manages.

For a pool or token the DEX sweep already priced the liquidity, so the read reuses that hint, no
second call. For any other contract a full read means summing native, stablecoin, and LP balances
priced to USD, which needs per-token balance calls and a price feed. The default seam reads the
native balance to prove the contract is live and holds gas, and notes that the priced token read
is the tracked next increment, so it reports a conservative figure rather than a guessed one. A
test injects its own seam.
"""

from __future__ import annotations

import json
import urllib.request

from opfor.scenarios.onchain.assets.contract.sources.observations import FundObservation

_TIMEOUT = 15.0
_RPC_URL = {"bsc": "https://bsc-dataseed.binance.org"}


def _native_wei(rpc_url: str, address: str) -> int:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance",
                          "params": [address, "latest"]}).encode("utf-8")
    request = urllib.request.Request(rpc_url, data=payload,
                                     headers={"Content-Type": "application/json",
                                              "User-Agent": "opfor-onchain/0.1"})
    with urllib.request.urlopen(request, timeout=_TIMEOUT) as response:
        data = json.loads(response.read().decode("utf-8"))
    return int(data.get("result") or "0x0", 16)


def read_funds(contract, hint_usd: float) -> FundObservation:
    """The funds the contract manages. A pool or token reuses the DEX liquidity hint. Any other
    contract reports the priced token read as unwired and falls back to a native-balance liveness
    check, so the figure is conservative, never guessed."""
    if hint_usd and hint_usd > 0:
        return FundObservation(funds_at_risk_usd=hint_usd, assets=("dex_liquidity",),
                               note="reused DEX sweep liquidity")
    rpc_url = _RPC_URL.get(contract.chain)
    if rpc_url is None:
        return FundObservation(note=f"no rpc configured for chain {contract.chain!r}")
    wei = _native_wei(rpc_url, contract.address)
    return FundObservation(
        funds_at_risk_usd=0.0, assets=("native",) if wei > 0 else (),
        note=f"native balance {wei} wei, priced token-balance read not wired in the default seam")

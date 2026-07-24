"""The RPC source seam, the default reads over a chain's public JSON-RPC endpoint.

It reads the funds a contract manages and whether an address is a contract. For a pool or token
the DEX sweep already priced the liquidity, so the funds read reuses that hint, no second call.
For any other contract a full read means summing native, stablecoin, and LP balances priced to
USD, which needs per-token balance calls and a price feed, the tracked next increment, so the
default reads the native balance to prove the contract is live and notes the priced read as
unwired. `is_contract` backs the pivot's filter, an address with code is a contract, an
externally owned account has none. A test injects its own seam.
"""

from __future__ import annotations

import json
import urllib.request

from opfor.scenarios.onchain.assets.contract.sources.observations import FundObservation

_TIMEOUT = 15.0
_RPC_URL = {"bsc": "https://bsc-dataseed.binance.org"}


def _rpc_call(rpc_url: str, method: str, params: list):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                          "params": params}).encode("utf-8")
    request = urllib.request.Request(rpc_url, data=payload,
                                     headers={"Content-Type": "application/json",
                                              "User-Agent": "opfor-onchain/0.1"})
    with urllib.request.urlopen(request, timeout=_TIMEOUT) as response:
        return json.loads(response.read().decode("utf-8")).get("result")


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
    wei = int(_rpc_call(rpc_url, "eth_getBalance", [contract.address, "latest"]) or "0x0", 16)
    return FundObservation(
        funds_at_risk_usd=0.0, assets=("native",) if wei > 0 else (),
        note=f"native balance {wei} wei, priced token-balance read not wired in the default seam")


def is_contract(address: str, chain: str) -> bool:
    """Whether the address holds code, so the pivot keeps a contract counterparty and drops an
    externally owned account. A chain with no RPC configured answers False, so the pivot degrades
    to no counterparties rather than failing the whole run."""
    rpc_url = _RPC_URL.get(chain)
    if rpc_url is None:
        return False
    code = _rpc_call(rpc_url, "eth_getCode", [address, "latest"])
    return isinstance(code, str) and code not in ("0x", "0x0", "")

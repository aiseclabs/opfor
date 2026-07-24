"""The RPC source seam, the low-level reads over a chain's public JSON-RPC endpoint.

It reads a native balance, an ERC20 token balance, and whether an address holds code. The funds
seam composes the balance reads with DEX prices, the pivot uses `is_contract` to keep a contract
counterparty and drop an externally owned account. A test injects its own callables, so no read
touches the network in a test.
"""

from __future__ import annotations

import json
import urllib.request

_TIMEOUT = 15.0
_RPC_URL = {"bsc": "https://bsc-dataseed.binance.org"}
# The ERC20 balanceOf selector, keccak("balanceOf(address)")[:4].
_BALANCE_OF = "0x70a08231"


def _rpc_call(rpc_url: str, method: str, params: list):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                          "params": params}).encode("utf-8")
    request = urllib.request.Request(rpc_url, data=payload,
                                     headers={"Content-Type": "application/json",
                                              "User-Agent": "opfor-onchain/0.1"})
    with urllib.request.urlopen(request, timeout=_TIMEOUT) as response:
        return json.loads(response.read().decode("utf-8")).get("result")


def native_wei(address: str, chain: str) -> int:
    """The native-coin balance of an address in wei, or 0 when the chain has no RPC configured."""
    rpc_url = _RPC_URL.get(chain)
    if rpc_url is None:
        return 0
    return int(_rpc_call(rpc_url, "eth_getBalance", [address, "latest"]) or "0x0", 16)


def token_balance(token: str, holder: str, chain: str) -> int:
    """The ERC20 balance of `holder` in `token`, raw, undivided by decimals. Zero when the chain has
    no RPC configured or the call returns empty."""
    rpc_url = _RPC_URL.get(chain)
    if rpc_url is None:
        return 0
    data = _BALANCE_OF + holder.lower().replace("0x", "").rjust(64, "0")
    result = _rpc_call(rpc_url, "eth_call", [{"to": token, "data": data}, "latest"])
    return int(result, 16) if result and result != "0x" else 0


def is_contract(address: str, chain: str) -> bool:
    """Whether the address holds code, so the pivot keeps a contract counterparty and drops an
    externally owned account. A chain with no RPC configured answers False, so the pivot degrades
    to no counterparties rather than failing the whole run."""
    rpc_url = _RPC_URL.get(chain)
    if rpc_url is None:
        return False
    code = _rpc_call(rpc_url, "eth_getCode", [address, "latest"])
    return isinstance(code, str) and code not in ("0x", "0x0", "")

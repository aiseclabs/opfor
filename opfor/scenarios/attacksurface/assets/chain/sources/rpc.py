"""The RPC source seam, the chain-state reads behind the funds and pivot steps.

It reads a native balance, an ERC20 token balance, a token's decimals, whether an address holds
code, and a proxy's implementation slot. A read is routed per chain. By default it goes through the
explorer's `proxy` module, the explorer's JSON-RPC pass-through, so it reaches the chain over the
one host and key the scenario already uses. The supported chains, Ethereum, Polygon, and Arbitrum,
are all fully covered by the free explorer key, so they take that path. `OPFOR_<CHAIN>_RPC` opts a
chain into a public node instead, the escape hatch for a chain the key rate-limits or does not
cover, so a gated chain can be read from a public node without a paid plan and without a code
change. A test injects its own callables, so no read touches the network.
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request

from opfor.scenarios.attacksurface.assets.chain.sources import etherscan

# The ERC20 balanceOf selector, keccak("balanceOf(address)")[:4].
_BALANCE_OF = "0x70a08231"
# The ERC20 decimals() selector, keccak("decimals()")[:4].
_DECIMALS = "0x313ce567"
# The EIP-1967 implementation storage slot, keccak("eip1967.proxy.implementation") - 1. A standard
# upgradeable proxy holds the address of the code behind it here, so reading the slot recovers the
# implementation the proxy forwards to, the contract that actually holds the auditable logic.
_EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"

# Default public nodes per chain, empty because every supported chain is covered by the explorer
# key. `OPFOR_<CHAIN>_RPC` opts a chain in when needed, so the routing stays a ready escape hatch
# for a gated or rate-limited chain without wiring a default here.
_PUBLIC_RPC: dict[str, tuple[str, ...]] = {}
_RPC_TIMEOUT = 12.0
_RPC_MIN_INTERVAL = 0.12
_RPC_LOCK = threading.Lock()
_rpc_next = [0.0]


def _public_endpoints(chain: str) -> tuple[str, ...]:
    """The public nodes for a chain, an env override first, or empty when the chain uses the
    explorer proxy. Empty is the default, so a chain the explorer key covers is unaffected."""
    override = os.environ.get(f"OPFOR_{chain.upper()}_RPC")
    defaults = _PUBLIC_RPC.get(chain, ())
    return ((override,) + defaults) if override else defaults


def _rpc_throttle() -> None:
    """Pace public-node calls so a full run does not trip a node's rate limit, across threads."""
    with _RPC_LOCK:
        now = time.monotonic()
        wait = _rpc_next[0] - now
        if wait > 0:
            time.sleep(wait)
        _rpc_next[0] = time.monotonic() + _RPC_MIN_INTERVAL


def _params_for(method: str, params: dict) -> list:
    """The flat explorer-proxy params rendered as the positional JSON-RPC params a raw node wants."""
    tag = params.get("tag", "latest")
    if method == "eth_call":
        return [{"to": params["to"], "data": params["data"]}, tag]
    if method == "eth_getStorageAt":
        return [params["address"], params["position"], tag]
    return [params["address"], tag]


def _public_call(endpoints: tuple[str, ...], method: str, params: dict):
    """One JSON-RPC call to the first node that answers, trying each endpoint in turn so a single
    node's outage or rate limit does not fail the read. Raises when every node fails, so a read that
    could not be made is loud, never a silent zero, invariant 5."""
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                       "params": _params_for(method, params)}).encode("utf-8")
    last: Exception | None = None
    for url in endpoints:
        _rpc_throttle()
        request = urllib.request.Request(url, data=body,
                                         headers={"Content-Type": "application/json",
                                                  "User-Agent": "opfor-onchain/0.1"})
        try:
            with urllib.request.urlopen(request, timeout=_RPC_TIMEOUT) as response:
                data = json.loads(response.read().decode("utf-8"))
            if isinstance(data, dict) and "result" in data:
                return data["result"]
            last = RuntimeError(f"node {url} returned no result: {str(data)[:120]}")
        except (urllib.error.URLError, ValueError, TimeoutError) as exc:
            last = exc
    raise RuntimeError(f"all public nodes failed for {method} on this chain: {last}")


def _call(chain: str, method: str, params: dict):
    """One chain-state read, from the chain's public node when it has one, else the explorer proxy."""
    endpoints = _public_endpoints(chain)
    if endpoints:
        return _public_call(endpoints, method, params)
    return etherscan.proxy(chain, method, params)


def _to_int(value) -> int:
    try:
        return int(value, 16) if isinstance(value, str) and value.startswith("0x") else 0
    except ValueError:
        return 0


def native_wei(address: str, chain: str) -> int:
    """The native-coin balance of an address in wei, or 0 when the read is empty."""
    return _to_int(_call(chain, "eth_getBalance", {"address": address, "tag": "latest"}))


def token_balance(token: str, holder: str, chain: str) -> int:
    """The ERC20 balance of `holder` in `token`, raw, undivided by decimals. Zero when the call
    returns empty."""
    data = _BALANCE_OF + holder.lower().replace("0x", "").rjust(64, "0")
    return _to_int(_call(chain, "eth_call", {"to": token, "data": data, "tag": "latest"}))


def token_decimals(token: str, chain: str) -> int:
    """The ERC20 decimals of a token, for pricing a balance the value-token table does not name.
    Falls back to 18, the common default, when the call is empty or returns an implausible value,
    so a non-standard token yields a conservative figure rather than a wild one."""
    result = _call(chain, "eth_call", {"to": token, "data": _DECIMALS, "tag": "latest"})
    decimals = _to_int(result)
    return decimals if 0 < decimals <= 36 else 18


def is_contract(address: str, chain: str) -> bool:
    """Whether the address holds code, so the pivot keeps a contract counterparty and drops an
    externally owned account."""
    code = _call(chain, "eth_getCode", {"address": address, "tag": "latest"})
    return isinstance(code, str) and code not in ("0x", "0x0", "")


def implementation_address(proxy: str, chain: str) -> str:
    """The implementation address behind an EIP-1967 proxy, read from its implementation storage
    slot, or empty when the slot is zero. The slot holds a 32-byte word whose low 20 bytes are the
    address, so auditing the implementation reaches the code the proxy runs, not the forwarding
    shell."""
    word = _call(chain, "eth_getStorageAt",
                 {"address": proxy, "position": _EIP1967_IMPL_SLOT, "tag": "latest"})
    if not isinstance(word, str) or not word.startswith("0x"):
        return ""
    address = "0x" + word[2:].rjust(64, "0")[-40:]
    return address if _to_int(address) != 0 else ""

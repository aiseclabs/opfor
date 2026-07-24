"""The RPC source seam, the chain-state reads behind the funds and pivot steps.

It reads a native balance, an ERC20 token balance, and whether an address holds code. The reads go
through the explorer's `proxy` module, the explorer's JSON-RPC pass-through, so they reach the
chain over the one host and key the scenario already uses rather than a separate node endpoint that
a network may not reach. The funds seam composes the balance reads with DEX prices, the pivot uses
`is_contract` to keep a contract counterparty and drop an externally owned account. A test injects
its own callables, so no read touches the network in a test.
"""

from __future__ import annotations

from opfor.scenarios.onchain.assets.contract.sources import etherscan

# The ERC20 balanceOf selector, keccak("balanceOf(address)")[:4].
_BALANCE_OF = "0x70a08231"
# The ERC20 decimals() selector, keccak("decimals()")[:4].
_DECIMALS = "0x313ce567"


def _to_int(value) -> int:
    try:
        return int(value, 16) if isinstance(value, str) and value.startswith("0x") else 0
    except ValueError:
        return 0


def native_wei(address: str, chain: str) -> int:
    """The native-coin balance of an address in wei, or 0 when the explorer is not configured."""
    return _to_int(etherscan.proxy(chain, "eth_getBalance", {"address": address, "tag": "latest"}))


def token_balance(token: str, holder: str, chain: str) -> int:
    """The ERC20 balance of `holder` in `token`, raw, undivided by decimals. Zero when the explorer
    is not configured or the call returns empty."""
    data = _BALANCE_OF + holder.lower().replace("0x", "").rjust(64, "0")
    return _to_int(etherscan.proxy(chain, "eth_call", {"to": token, "data": data, "tag": "latest"}))


def token_decimals(token: str, chain: str) -> int:
    """The ERC20 decimals of a token, for pricing a balance the value-token table does not name.
    Falls back to 18, the common default, when the call is empty or returns an implausible value,
    so a non-standard token yields a conservative figure rather than a wild one."""
    result = etherscan.proxy(chain, "eth_call", {"to": token, "data": _DECIMALS, "tag": "latest"})
    decimals = _to_int(result)
    return decimals if 0 < decimals <= 36 else 18


def is_contract(address: str, chain: str) -> bool:
    """Whether the address holds code, so the pivot keeps a contract counterparty and drops an
    externally owned account. An unconfigured explorer answers False, so the pivot degrades to no
    counterparties rather than failing the whole run."""
    code = etherscan.proxy(chain, "eth_getCode", {"address": address, "tag": "latest"})
    return isinstance(code, str) and code not in ("0x", "0x0", "")

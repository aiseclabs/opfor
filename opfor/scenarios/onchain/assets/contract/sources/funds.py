"""The funds source seam, the default priced read of the value a contract manages.

For a pool or token the DEX sweep already priced the liquidity, so the read reuses that hint. For
any other contract it reads the contract's balance of a set of value tokens, native coin, stables,
and majors, prices each, and sums the USD it can account for. It is conservative by construction,
it counts only tokens it can both read and price, and it names what it counted, so the figure is a
floor, never a guess. The balance reads and the price lookup are injected, so the summing logic is
tested with fixtures and the default wiring speaks to the live RPC and DEX.
"""

from __future__ import annotations

import re

from opfor.scenarios.onchain.assets.contract.chains import ChainPolicy, default_chain_policy
from opfor.scenarios.onchain.assets.contract.sources import dex, rpc
from opfor.scenarios.onchain.assets.contract.sources.observations import FundObservation

# A 20-byte EVM address, `0x` and forty hex digits. A discovery source can hand back a 32-byte pool
# id or some other identifier that is not an address, and priced against it the figure is noise, so
# the sweep keeps only nodes whose address is well formed.
_EVM_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")


def is_evm_address(address: str) -> bool:
    """Whether a string is a well-formed 20-byte EVM address."""
    return bool(_EVM_ADDRESS.match(address or ""))

def value_token_addresses(chain: str, policy: ChainPolicy | None = None) -> frozenset[str]:
    """The value-token addresses for a chain, lowercased. The pivot uses this to skip pivoting a
    money token such as WETH or a stable, which is a quote token in half the pools on the chain and
    would pull the whole DeFi ecosystem back as counterparties, not a project's fund contracts. The
    policy carries the table, loaded from data, the packaged default when none is passed."""
    return (policy or default_chain_policy()).value_token_addresses(chain)


def value_tokens_for(contract, *, decimals_fn, policy: ChainPolicy | None = None):
    """The value tokens to price for a contract, the chain's base set plus the project token the
    contract was pivoted from. This is the fix for the long tail, a new project's vault holds its
    own token, not a stable, so a table of stables alone reads its funds as zero. The project token
    is priced like any other priced token, its decimals read live since a project token is not in
    the static table."""
    policy = policy or default_chain_policy()
    tokens = list(policy.base_value_tokens(contract.chain))
    project = (contract.related_to or "").strip()
    known = {address.lower() for address, _, _, _ in tokens}
    if project and project.lower() not in known:
        symbol = contract.base_symbol or "PROJECT"
        tokens.append((project, symbol, "priced", decimals_fn(project, contract.chain)))
    return tuple(tokens)


def compute_funds(contract, *, native_wei_fn, token_balance_fn, price_fn, value_tokens,
                  native_decimals: int = 18):
    """Sum the USD the contract holds across the native coin and the value tokens. Pure, the three
    reads are injected. The native price is the wrapped-native price, the first entry, read once.
    Each token is divided by its own decimals, since a stable is 6 decimals on Ethereum."""
    total = 0.0
    assets: list[str] = []
    native_price = price_fn(value_tokens[0][0], contract.chain) or 0.0
    native = native_wei_fn(contract.address, contract.chain) / 10 ** native_decimals * native_price
    if native > 0:
        total += native
        assets.append("native")
    for address, symbol, kind, decimals in value_tokens:
        raw = token_balance_fn(address, contract.address, contract.chain)
        if raw <= 0:
            continue
        amount = raw / 10 ** decimals
        if kind == "stable":
            price = 1.0
        elif kind == "native":
            price = native_price
        else:
            price = price_fn(address, contract.chain) or 0.0
        value = amount * price
        if value > 0:
            total += value
            assets.append(symbol)
    return total, tuple(dict.fromkeys(assets))


def read_funds(contract, hint_usd: float, policy: ChainPolicy | None = None) -> FundObservation:
    """The funds the contract manages. A pool or token reuses the DEX liquidity hint. Any other
    contract is priced across the value-token set, a conservative floor that names what it counted.
    The policy carries the value-token table, the packaged default when none is injected."""
    policy = policy or default_chain_policy()
    if hint_usd and hint_usd > 0:
        return FundObservation(funds_at_risk_usd=hint_usd, assets=("dex_liquidity",),
                               note="reused DEX sweep liquidity")
    if not policy.has_chain(contract.chain):
        return FundObservation(note=f"no value-token table for chain {contract.chain!r}")
    value_tokens = value_tokens_for(contract, decimals_fn=rpc.token_decimals, policy=policy)
    total, assets = compute_funds(contract, native_wei_fn=rpc.native_wei,
                                  token_balance_fn=rpc.token_balance, price_fn=dex.token_price_usd,
                                  value_tokens=value_tokens, native_decimals=policy.native_decimals)
    note = "priced native, value-token, and project-token balances" if total > 0 else "no priced balance held"
    return FundObservation(funds_at_risk_usd=total, assets=assets, note=note)

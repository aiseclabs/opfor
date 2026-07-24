"""The funds source seam, the default priced read of the value a contract manages.

For a pool or token the DEX sweep already priced the liquidity, so the read reuses that hint. For
any other contract it reads the contract's balance of a set of value tokens, native coin, stables,
and majors, prices each, and sums the USD it can account for. It is conservative by construction,
it counts only tokens it can both read and price, and it names what it counted, so the figure is a
floor, never a guess. The balance reads and the price lookup are injected, so the summing logic is
tested with fixtures and the default wiring speaks to the live RPC and DEX.
"""

from __future__ import annotations

from opfor.scenarios.onchain.assets.contract.sources import dex, rpc
from opfor.scenarios.onchain.assets.contract.sources.observations import FundObservation

# The value tokens per chain, the assets counted toward funds at risk. Each entry carries its own
# decimals, since a stable is 6 decimals on Ethereum but 18 on BSC. `native` prices at the
# native-coin price, `stable` at one dollar, `priced` at the token's own DEX price. The native coin
# itself is 18 decimals on both chains. A broader set is a data change here, not a code change.
_NATIVE_DECIMALS = 18
_VALUE_TOKENS = {
    "ethereum": (
        ("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "WETH", "native", 18),
        ("0xdAC17F958D2ee523a2206206994597C13D831ec7", "USDT", "stable", 6),
        ("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "USDC", "stable", 6),
        ("0x6B175474E89094C44Da98b954EedeAC495271d0F", "DAI", "stable", 18),
        ("0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599", "WBTC", "priced", 8),
    ),
    "bsc": (
        ("0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c", "WBNB", "native", 18),
        ("0x55d398326f99059fF775485246999027B3197955", "USDT", "stable", 18),
        ("0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d", "USDC", "stable", 18),
        ("0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56", "BUSD", "stable", 18),
        ("0x7130d2A12B9BCbFAe4f2634d864A1Ee1Ce3Ead9c", "BTCB", "priced", 18),
        ("0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82", "CAKE", "priced", 18),
    ),
}


def value_token_addresses(chain: str) -> frozenset[str]:
    """The value-token addresses for a chain, lowercased. The pivot uses this to skip pivoting a
    money token such as WETH or a stable, which is a quote token in half the pools on the chain and
    would pull the whole DeFi ecosystem back as counterparties, not a project's fund contracts."""
    return frozenset(address.lower() for address, _, _, _ in _VALUE_TOKENS.get(chain, ()))


def value_tokens_for(contract, *, decimals_fn):
    """The value tokens to price for a contract, the chain's base set plus the project token the
    contract was pivoted from. This is the fix for the long tail, a new project's vault holds its
    own token, not a stable, so a table of stables alone reads its funds as zero. The project token
    is priced like any other priced token, its decimals read live since a project token is not in
    the static table."""
    tokens = list(_VALUE_TOKENS.get(contract.chain, ()))
    project = (contract.related_to or "").strip()
    known = {address.lower() for address, _, _, _ in tokens}
    if project and project.lower() not in known:
        symbol = contract.base_symbol or "PROJECT"
        tokens.append((project, symbol, "priced", decimals_fn(project, contract.chain)))
    return tuple(tokens)


def compute_funds(contract, *, native_wei_fn, token_balance_fn, price_fn, value_tokens):
    """Sum the USD the contract holds across the native coin and the value tokens. Pure, the three
    reads are injected. The native price is the wrapped-native price, the first entry, read once.
    Each token is divided by its own decimals, since a stable is 6 decimals on Ethereum."""
    total = 0.0
    assets: list[str] = []
    native_price = price_fn(value_tokens[0][0], contract.chain) or 0.0
    native = native_wei_fn(contract.address, contract.chain) / 10 ** _NATIVE_DECIMALS * native_price
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


def read_funds(contract, hint_usd: float) -> FundObservation:
    """The funds the contract manages. A pool or token reuses the DEX liquidity hint. Any other
    contract is priced across the value-token set, a conservative floor that names what it counted."""
    if hint_usd and hint_usd > 0:
        return FundObservation(funds_at_risk_usd=hint_usd, assets=("dex_liquidity",),
                               note="reused DEX sweep liquidity")
    if contract.chain not in _VALUE_TOKENS:
        return FundObservation(note=f"no value-token table for chain {contract.chain!r}")
    value_tokens = value_tokens_for(contract, decimals_fn=rpc.token_decimals)
    total, assets = compute_funds(contract, native_wei_fn=rpc.native_wei,
                                  token_balance_fn=rpc.token_balance, price_fn=dex.token_price_usd,
                                  value_tokens=value_tokens)
    note = "priced native, value-token, and project-token balances" if total > 0 else "no priced balance held"
    return FundObservation(funds_at_risk_usd=total, assets=assets, note=note)

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

# The value tokens per chain, the assets counted toward funds at risk. Each is 18 decimals on BSC,
# including the stables, unlike their 6-decimal Ethereum forms. `native` prices at the native-coin
# price, `stable` at one dollar, `priced` at the token's own DEX price. A broader set is a data
# change here, not a code change.
_DECIMALS = 18
_VALUE_TOKENS = {
    "bsc": (
        ("0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c", "WBNB", "native"),
        ("0x55d398326f99059fF775485246999027B3197955", "USDT", "stable"),
        ("0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d", "USDC", "stable"),
        ("0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56", "BUSD", "stable"),
        ("0x1AF3F329e8BE154074D8769D1FFa4eE058B1DBc3", "DAI", "stable"),
        ("0x7130d2A12B9BCbFAe4f2634d864A1Ee1Ce3Ead9c", "BTCB", "priced"),
        ("0x2170Ed0880ac9A755fd29B2688956BD959F933F8", "ETH", "priced"),
        ("0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82", "CAKE", "priced"),
    ),
}


def compute_funds(contract, *, native_wei_fn, token_balance_fn, price_fn, value_tokens):
    """Sum the USD the contract holds across the native coin and the value tokens. Pure, the three
    reads are injected. The native price is the WBNB price, the first entry, read once."""
    total = 0.0
    assets: list[str] = []
    native_price = price_fn(value_tokens[0][0], contract.chain) or 0.0
    native = native_wei_fn(contract.address, contract.chain) / 10 ** _DECIMALS * native_price
    if native > 0:
        total += native
        assets.append("native")
    for address, symbol, kind in value_tokens:
        raw = token_balance_fn(address, contract.address, contract.chain)
        if raw <= 0:
            continue
        amount = raw / 10 ** _DECIMALS
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
    value_tokens = _VALUE_TOKENS.get(contract.chain)
    if not value_tokens:
        return FundObservation(note=f"no value-token table for chain {contract.chain!r}")
    total, assets = compute_funds(contract, native_wei_fn=rpc.native_wei,
                                  token_balance_fn=rpc.token_balance, price_fn=dex.token_price_usd,
                                  value_tokens=value_tokens)
    note = "priced native and value-token balances" if total > 0 else "no priced value-token balance held"
    return FundObservation(funds_at_risk_usd=total, assets=assets, note=note)

"""The pivot seam, from a token to the fund-management contracts behind it.

The shallow half, keyless, finds the pools a token trades in, the layer triage downgrades. The
deep half is the point of the scenario, it finds the contracts that custody the token, the
staking, farm, vault, or locker actually worth auditing. It reads the token's recent transfer
history from the explorer, ranks the counterparties by how often they move the token, keeps the
ones that hold code, an externally owned account is dropped, and emits them for enrichment to
classify. The transfer read and the code check are injected, so the pure ranking logic is tested
with fixtures and the default wiring speaks to the live explorer and RPC.

The deep half needs an explorer key, so without one the pivot degrades to the shallow pools
rather than failing, and the run says as much through the empty counterparty set.
"""

from __future__ import annotations

from collections import Counter

from opfor.scenarios.attacksurface.assets.chain.chains import ChainPolicy, default_chain_policy
from opfor.scenarios.attacksurface.assets.chain.sources import dexscreener, etherscan, funds, rpc
from opfor.scenarios.attacksurface.assets.chain.sources.observations import RelatedObservation

# How many recent transfers to read, how many top counterparties to code-check, and how many
# fund contracts to keep. Each bounds a fan-out that would otherwise flood MAP.
_TRANSFER_SCAN = 200
_COUNTERPARTY_CHECK = 12
_MAX_DEEP = 5


def counterparty_pivot(contract, *, fetch_transfers, is_contract, max_deep=_MAX_DEEP,
                       policy: ChainPolicy | None = None):
    """The pure deep-pivot logic. Rank the token's transfer counterparties by frequency, keep the
    contracts, and emit them as related. `fetch_transfers(address, chain)` returns transfer records
    with `from` and `to`, `is_contract(address, chain)` decides code presence. Both are injected,
    so this is tested with no network. The policy carries the burn and mint sinks dropped before
    ranking, shared with the sweep, the packaged default when none is passed."""
    policy = policy or default_chain_policy()
    token = contract.address.lower()
    counts: Counter[str] = Counter()
    for transfer in fetch_transfers(contract.address, contract.chain):
        for side in ("from", "to"):
            addr = (transfer.get(side) or "").lower()
            if addr and addr != token and not policy.is_null(addr):
                counts[addr] += 1
    related: list[RelatedObservation] = []
    for addr, _ in counts.most_common(_COUNTERPARTY_CHECK):
        if is_contract(addr, contract.chain):
            related.append(RelatedObservation(address=addr, chain=contract.chain,
                                              role_hint="unknown", via="transfer counterparty"))
        if len(related) >= max_deep:
            break
    return related


def _etherscan_transfers(address: str, chain: str) -> list[dict]:
    """Read the token's recent transfers from the explorer. Needs a key, so without one it returns
    no transfers and the deep pivot degrades to the shallow pools. The free key also gates the
    transfer module on some chains, BSC among them, and that denial is caught here so the deep pivot
    degrades to shallow rather than failing the whole pivot, while a real error still propagates."""
    if not etherscan.configured(chain):
        return []
    try:
        data = etherscan.get(chain, {"module": "account", "action": "tokentx",
                                     "contractaddress": address, "page": "1",
                                     "offset": str(_TRANSFER_SCAN), "sort": "desc"})
    except etherscan.AccessDenied:
        return []
    result = data.get("result")
    return result if isinstance(result, list) else []


def pivot(contract, policy: ChainPolicy | None = None) -> tuple[RelatedObservation, ...]:
    """The default pivot, shallow pools always plus deep fund contracts when a key is set. Only a
    token is pivoted, a pool is already the leaf a token pointed at. Deduped by address, the
    shallow pools first so a contract seen both ways keeps its richer origin. The policy carries the
    value-token set, the packaged default when none is passed."""
    policy = policy or default_chain_policy()
    if contract.role != "token":
        return ()
    # A money token, WETH or a stable, is a quote token across the chain, so pivoting it would pull
    # the whole ecosystem back rather than one project's fund contracts. Skip it.
    if contract.address.lower() in policy.value_token_addresses(contract.chain):
        return ()
    related: dict[str, RelatedObservation] = {}
    for obs in dexscreener.pivot(contract):
        related[obs.address.lower()] = obs
    for obs in counterparty_pivot(contract, fetch_transfers=_etherscan_transfers,
                                  is_contract=rpc.is_contract, policy=policy):
        related.setdefault(obs.address.lower(), obs)
    return tuple(related.values())

"""The structural target filter, shared by triage and the report.

A contract is excluded from the audit surface on structural grounds, facts about what it is rather
than a verdict on it: the raw DEX layer, a value token, a null or burn sink, a malformed address,
or known audited infrastructure. Triage reads this to decide what it judges, and the report reads
it to tag which inventory records are audit targets, so the exported target set matches the queue
triage judges rather than diverging from it. Keeping the one predicate here is why the two never
drift, the divergence the target-selection analysis found, where the report listed infrastructure
that triage had already dropped.
"""

from __future__ import annotations

from opfor.scenarios.onchain.assets.contract.sources.funds import (
    NULL_ADDRESSES,
    is_evm_address,
    value_token_addresses,
)

# The DEX-layer roles, a raw pair or a plain token, not an audit target on their own. The pivot's
# job is to reach the fund contract behind them, and that is what is judged.
_DEX_LAYER_ROLES = ("pool", "token")


def structural_exclusion(chain: str, address: str, role: str,
                         known_infrastructure: dict[str, frozenset[str]] | None,
                         is_implementation: bool = False, is_vendored: bool = False) -> str | None:
    """Why a contract is not an audit target on structural grounds, or None when it is a candidate.

    The reason is a short slug, so the report can record why a contract was excluded rather than
    dropping it silently. None means the contract passes the structural filter and is a candidate,
    whether it then rises to a finding is triage's model call. A proxy implementation is exempt from
    the DEX-layer rule, it was resolved deliberately as the code behind a funded proxy, so even when
    the model reads its token-like ABI as `token` it is logic worth auditing, not a raw pair. A
    contract whose every source file is a third-party library is a dependency copy, not a project's
    own code, so it is excluded as vendored.
    """
    if not is_evm_address(address):
        return "malformed-address"
    addr = address.lower()
    if is_vendored:
        return "vendored-library"
    if role in _DEX_LAYER_ROLES and not is_implementation:
        return "dex-layer"
    if addr in NULL_ADDRESSES:
        return "null-address"
    if addr in value_token_addresses(chain):
        return "value-token"
    if addr in (known_infrastructure or {}).get(chain, frozenset()):
        return "known-infrastructure"
    return None

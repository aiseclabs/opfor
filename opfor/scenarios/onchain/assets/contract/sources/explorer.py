"""The explorer source seam, the default verified-source and ABI read.

It reads a block explorer's verified source and ABI for one address over the Etherscan V2 API. The
explorer needs a key, so without one it reports source unavailable rather than guessing a contract
is verified, the honest default the tool holds itself to. A test injects its own seam, so the
class's logic never depends on a live key.
"""

from __future__ import annotations

import json

from opfor.scenarios.onchain.assets.contract.sources import etherscan
from opfor.scenarios.onchain.assets.contract.sources.observations import SourceObservation


def _abi_functions(abi_text: str) -> tuple[str, ...]:
    """The external and public function names from an ABI json string, deduped and ordered. A view
    function is dropped, so the interface enumeration weighs the state-changing surface."""
    try:
        abi = json.loads(abi_text)
    except (TypeError, ValueError):
        return ()
    names = [entry.get("name", "") for entry in abi
             if entry.get("type") == "function"
             and entry.get("stateMutability") not in ("view", "pure")
             and entry.get("name")]
    return tuple(dict.fromkeys(names))


def fetch_source(contract) -> SourceObservation:
    """Read verified source and ABI for the contract, or report why it was unavailable."""
    if not etherscan.configured(contract.chain):
        if etherscan.chain_id(contract.chain) is None:
            return SourceObservation(note=f"no explorer configured for chain {contract.chain!r}")
        return SourceObservation(note="no explorer key set, OPFOR_ETHERSCAN_API_KEY unset")
    data = etherscan.get(contract.chain, {"module": "contract", "action": "getsourcecode",
                                          "address": contract.address})
    result = data.get("result")
    entry = result[0] if isinstance(result, list) and result else {}
    source_text = entry.get("SourceCode") or ""
    abi_text = entry.get("ABI") or ""
    verified = bool(source_text) and abi_text not in ("", "Contract source code not verified")
    return SourceObservation(
        verified=verified, functions=_abi_functions(abi_text) if verified else (),
        source_text=source_text if verified else "",
        note="" if verified else "explorer served no verified source")

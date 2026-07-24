"""The explorer source seam, the default verified-source and ABI read.

It reads a block explorer's verified source and ABI for one address. The explorer needs an API
key, from `OPFOR_EXPLORER_KEY`, so without a key it reports source unavailable rather than
guessing a contract is verified, the honest default the tool holds itself to. A test injects its
own seam, so the class's logic never depends on a live key.
"""

from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request

from opfor.scenarios.onchain.assets.contract.sources.observations import SourceObservation

_TIMEOUT = 15.0
# The explorer API base per chain. One chain to start, a second chain swaps this map, not the
# class, the same way the domain class generalizes a source.
_EXPLORER_BASE = {"bsc": "https://api.bscscan.com/api"}


def _get_json(url: str):
    request = urllib.request.Request(url, headers={"User-Agent": "opfor-onchain/0.1"})
    with urllib.request.urlopen(request, timeout=_TIMEOUT) as response:
        return json.loads(response.read().decode("utf-8"))


def _abi_functions(abi_text: str) -> tuple[str, ...]:
    """The external and public function names from an ABI json string, deduped and ordered."""
    try:
        abi = json.loads(abi_text)
    except (TypeError, ValueError):
        return ()
    names = [entry.get("name", "") for entry in abi
             if entry.get("type") == "function"
             and entry.get("stateMutability") != "view"
             and entry.get("name")]
    return tuple(dict.fromkeys(names))


def fetch_source(contract) -> SourceObservation:
    """Read verified source and ABI for the contract, or report why it was unavailable."""
    base = _EXPLORER_BASE.get(contract.chain)
    if base is None:
        return SourceObservation(note=f"no explorer configured for chain {contract.chain!r}")
    key = os.environ.get("OPFOR_EXPLORER_KEY")
    if not key:
        return SourceObservation(note="no explorer key set, OPFOR_EXPLORER_KEY unset")
    query = urllib.parse.urlencode(
        {"module": "contract", "action": "getsourcecode", "address": contract.address, "apikey": key})
    data = _get_json(f"{base}?{query}")
    result = (data.get("result") or [{}])[0] if isinstance(data.get("result"), list) else {}
    source_text = result.get("SourceCode") or ""
    abi_text = result.get("ABI") or ""
    verified = bool(source_text) and abi_text not in ("", "Contract source code not verified")
    return SourceObservation(
        verified=verified, functions=_abi_functions(abi_text) if verified else (),
        source_text=source_text if verified else "",
        note="" if verified else "explorer served no verified source")

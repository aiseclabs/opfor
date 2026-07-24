"""The contract class source seams, the injected boundaries to public chain data.

Each module is one public source, the DEX index, the block explorer, and the RPC. The scenario
wires these defaults, a test injects its own, so the class's logic never touches the network in a
test. The seams return the typed observations in `observations`, never a loose dict.
"""

from __future__ import annotations

from opfor.scenarios.onchain.assets.contract.sources import dex, explorer, rpc

sweep = dex.sweep
pivot = dex.pivot
fetch_source = explorer.fetch_source
read_funds = rpc.read_funds

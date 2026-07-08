"""The chainscout scenario: discover valuable, risky on-chain contracts.

A standalone red-team recon scenario. From an `evm_chain` seed it discovers the
richest contracts on a chain (DeFiLlama), enriches each with per-contract risk
flags (GoPlus) and verification/compiler metadata (Etherscan), and escalates each
into a candidate audit target for triage to rank. It produces a prioritized list
of "holds value and shows risk signals" contracts; it never touches a contract
and never claims a contract is exploitable, only that it is worth a closer look.

Everything it does is a passive read of a public source, so all its work is osint
recon tier and needs no per-contract authorization. First chain is BSC; adding a
chain is a data change (a new entry in sources.CHAINS plus a campaign seed), not
an engine change.
"""

from __future__ import annotations

from pathlib import Path

from opfor.scenarios.base import ControlScenario
from opfor.scenarios.chainscout.executors import default_executors
from opfor.scenarios.chainscout.planner import ChainscoutPlanner

CHAINSCOUT = ControlScenario(
    name="chainscout",
    content_root=Path(__file__).resolve().parent,
    executors=default_executors(),
    planner=ChainscoutPlanner(),
)

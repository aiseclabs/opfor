"""The chainscout scenario: discover fresh, valuable, custom on-chain contracts.

A standalone red-team recon scenario. From an `evm_chain` seed it discovers the
contracts that actually hold value on a chain (Moralis token holders), dates each
one by its first transaction (Moralis), and enriches each with metadata
(Etherscan) and risk flags (GoPlus), then escalates each into a candidate audit
target for triage to rank. Value is a gate; priority is recency-first, so the
list surfaces fresh, custom code holding money rather than audited multisigs and
treasuries. It never touches a contract and never claims one is exploitable, only
that it is worth a closer look.

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

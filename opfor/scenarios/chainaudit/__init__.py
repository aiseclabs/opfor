"""The chainaudit scenario, an authorized on-chain contract audit loop.

opfor owns the orchestration and campaign state; codejury owns source acquisition
and security judgment. For each authorized EVM contract the scenario fetches the
verified source through codejury, runs the coded EVM Repo Review over it, and
records the workflow, the report paths, and a finding summary on the graph. It
adds no vulnerability-detection logic of its own and never parses block-explorer
responses, that all lives in codejury.

First supported chain is BSC; the design stays EVM-generic so later chains are a
data change (a new campaign target), not an engine change.
"""

from __future__ import annotations

from pathlib import Path

from opfor.scenarios.base import ControlScenario
from opfor.scenarios.chainaudit.executors import default_executors
from opfor.scenarios.chainaudit.planner import ChainauditPlanner

CHAINAUDIT = ControlScenario(
    name="chainaudit",
    content_root=Path(__file__).resolve().parent,
    executors=default_executors(),
    planner=ChainauditPlanner(),
)

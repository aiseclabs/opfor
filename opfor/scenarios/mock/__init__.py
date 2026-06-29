"""The mock scenario, a no-network world for offline tests."""

from __future__ import annotations

from pathlib import Path

from opfor.scenarios.base import ControlScenario
from opfor.scenarios.mock.executors import default_executors
from opfor.scenarios.mock.planner import MockPlanner

MOCK = ControlScenario(
    name="mock",
    content_root=Path(__file__).resolve().parent,
    executors=default_executors(),
    planner=MockPlanner(),
)

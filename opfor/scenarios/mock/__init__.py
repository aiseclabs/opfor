"""The mock scenario, a no-network world for offline tests."""

from __future__ import annotations

from pathlib import Path

from opfor.plugins.registry import register_hand
from opfor.scenarios.base import Scenario
from opfor.scenarios.mock.hand import MockHand

register_hand(MockHand())

MOCK = Scenario(
    name="mock",
    hand_name="mock",
    content_root=Path(__file__).resolve().parent,
)

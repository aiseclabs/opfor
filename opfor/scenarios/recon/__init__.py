"""The recon scenario, attack-surface discovery from a company's seed domains."""

from __future__ import annotations

from pathlib import Path

from opfor.plugins.registry import register_hand
from opfor.scenarios.base import Scenario
from opfor.scenarios.recon.hand import ReconHand

register_hand(ReconHand())

RECON = Scenario(
    name="recon",
    hand_name="recon",
    content_root=Path(__file__).resolve().parent,
)

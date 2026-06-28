"""The recon scenario, attack-surface discovery from a company's seed domains."""

from __future__ import annotations

from pathlib import Path

import yaml

from opfor.plugins.registry import register_hand
from opfor.scenarios.base import Scenario
from opfor.scenarios.recon.hand import ReconHand

# Security checks are data. The scenario loads them and wires them into the hand,
# so the hand never reads knowledge, it just applies the checks it is handed.
_CHECKS = yaml.safe_load((Path(__file__).resolve().parent / "checks.yaml").read_text())

register_hand(ReconHand(checks=_CHECKS))

RECON = Scenario(
    name="recon",
    hand_name="recon",
    content_root=Path(__file__).resolve().parent,
)

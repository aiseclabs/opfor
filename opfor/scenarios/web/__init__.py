"""The web scenario, a thin HTTP hand plus its playbooks."""

from __future__ import annotations

from pathlib import Path

from opfor.plugins.registry import register_hand
from opfor.scenarios.base import Scenario
from opfor.scenarios.web.hand import WebHand

register_hand(WebHand())

WEB = Scenario(
    name="web",
    hand_name="web",
    content_root=Path(__file__).resolve().parent,
)

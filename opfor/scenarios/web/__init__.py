"""The web scenario, a real HTTP crawler on the control shell."""

from __future__ import annotations

from pathlib import Path

from opfor.scenarios.base import ControlScenario
from opfor.scenarios.web.executors import default_executors
from opfor.scenarios.web.planner import WebPlanner

WEB = ControlScenario(
    name="web",
    content_root=Path(__file__).resolve().parent,
    executors=default_executors(),
    planner=WebPlanner(),
)

"""The recon scenario, on the task-graph control shell.

A bundle of capability executors plus a deterministic planner. Security checks
are data (`checks.yaml`) wired into the planner, which emits one check task per
service per check. The executors stay thin and the engine stays generic.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from opfor.scenarios.base import ControlScenario
from opfor.scenarios.recon.executors import default_executors
from opfor.scenarios.recon.planner import ReconPlanner

_CHECKS = yaml.safe_load((Path(__file__).resolve().parent / "checks.yaml").read_text())

RECON = ControlScenario(
    name="recon",
    content_root=Path(__file__).resolve().parent,
    executors=default_executors(),
    planner=ReconPlanner(_CHECKS),
)

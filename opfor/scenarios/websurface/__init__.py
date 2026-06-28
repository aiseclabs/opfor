"""The websurface scenario: recon plus endpoint discovery in one loop.

Composes the recon planner (org -> domains -> services) with the endpoint planner
(services -> endpoints). On the blackboard the control shell sequences it
naturally: as services appear, their endpoints get discovered, all passive work
gated to recon tier. This is the two-level fanout, asset then interface, end to
end and fully automatic.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from opfor.agent.planner import CompositePlanner
from opfor.scenarios.base import ControlScenario
from opfor.scenarios.recon.endpoints import EndpointPlanner, endpoint_executors
from opfor.scenarios.recon.executors import default_executors as recon_executors
from opfor.scenarios.recon.planner import ReconPlanner

_CHECKS = yaml.safe_load((Path(__file__).resolve().parents[1] / "recon" / "checks.yaml").read_text())

WEBSURFACE = ControlScenario(
    name="websurface",
    content_root=Path(__file__).resolve().parent,
    executors={**recon_executors(), **endpoint_executors()},
    planner=CompositePlanner([ReconPlanner(_CHECKS), EndpointPlanner()]),
)

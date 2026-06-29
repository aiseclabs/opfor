"""The aiagent scenario: prompt-injection red-teaming of an LLM endpoint.

A non-web attack surface proving the engine is generic: a brand-new scenario is
data (injection knowledge) plus a thin executor and a planner, with zero change
to the engine. It reuses the same blackboard, control shell, scope gate, and
verdict mechanism as the web scenarios.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from opfor.scenarios.aiagent.executors import default_executors
from opfor.scenarios.aiagent.planner import AiAgentPlanner
from opfor.scenarios.base import ControlScenario

_INJECTIONS = yaml.safe_load((Path(__file__).resolve().parent / "injections.yaml").read_text())

AIAGENT = ControlScenario(
    name="aiagent",
    content_root=Path(__file__).resolve().parent,
    executors=default_executors(),
    planner=AiAgentPlanner(_INJECTIONS),
)

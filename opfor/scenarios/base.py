"""ControlScenario, a bundle of executors plus a planner for the control shell.

A scenario supplies the capability executors (one tool each) and the planner that
decides which tasks to run against the situation graph. The engine never imports
a scenario, the runner resolves one and hands the control shell its executors and
planner. Knowledge (markdown playbooks, checks) lives under content_root and is
read by planners, never by an executor.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from opfor.plugins.base import Executor


@dataclass(frozen=True, kw_only=True)
class ControlScenario:
    """A scenario that runs on the task-graph control shell (PEP)."""

    name: str
    content_root: Path
    executors: dict[str, Executor]
    planner: Any  # opfor.agent.planner.Planner

    @property
    def knowledge_dir(self) -> Path:
        return self.content_root / "knowledge"

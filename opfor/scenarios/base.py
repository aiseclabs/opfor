"""Scenario, a bundle of one hand plus its knowledge tree.

A scenario binds the thin hand to the markdown playbooks the agent reads. The
engine never imports a scenario, the runner resolves one and hands the engine a
hand and a playbook string. The playbook is concatenated from the knowledge
tree, and crucially it is read here, for the agent, never by the hand.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from opfor.plugins.base import Executor, Hand
from opfor.plugins.registry import get_hand


@dataclass(frozen=True, kw_only=True)
class Scenario:
    name: str
    hand_name: str
    content_root: Path

    @property
    def knowledge_dir(self) -> Path:
        return self.content_root / "knowledge"

    def hand(self) -> Hand:
        return get_hand(self.hand_name)

    def playbook(self) -> str:
        """Concatenate the knowledge index and every playbook into one string."""
        parts: list[str] = []
        index = self.knowledge_dir / "index.md"
        if index.exists():
            parts.append(index.read_text())
        playbooks_dir = self.knowledge_dir / "playbooks"
        if playbooks_dir.exists():
            for md in sorted(playbooks_dir.glob("*.md")):
                parts.append(md.read_text())
        if not parts:
            raise FileNotFoundError(f"no knowledge under {self.knowledge_dir}")
        return "\n\n".join(parts)


@dataclass(frozen=True, kw_only=True)
class ControlScenario:
    """A scenario that runs on the task-graph control shell (PEP).

    It supplies the executors (one per capability) and a planner, instead of a
    single hand and a brain. The engine stays scenario-blind.
    """

    name: str
    content_root: Path
    executors: dict[str, Executor]
    planner: Any  # opfor.agent.planner.Planner

"""The task graph, the control shell's unit of work.

A Task is one thing for one executor to do against one target. The TaskGraph
holds tasks by id with a status, dedupes by id (so a planner can naively re-emit
applicable tasks every round without duplicating work), and reports which tasks
are ready to run right now. Readiness plus the situation graph is how the
pokeable surface is computed live: a planner emits a task only once its
preconditions hold, and the control shell runs every ready task it sees.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

_PENDING = "pending"
_RUNNING = "running"
_DONE = "done"


@dataclass(frozen=True, kw_only=True)
class Task:
    """One unit of work. capability selects the executor, target names the node."""

    id: str
    capability: str
    target: str
    params: dict[str, Any] = field(default_factory=dict)
    tier: str = "recon"
    scope_host: str | None = None
    osint: bool = False
    deps: tuple[str, ...] = ()
    # The planner's belief (0..1) that this task is worth running. 1.0 = certain
    # (the default, so existing planners are unaffected). A run can set a floor to
    # prune low-confidence work; see opfor.agent.confidence for the bands.
    confidence: float = 1.0


class TaskGraph:
    """Tasks keyed by id with a status, plus the ready set."""

    def __init__(self) -> None:
        self._tasks: dict[str, Task] = {}
        self._status: dict[str, str] = {}

    def add(self, task: Task) -> bool:
        """Register a task, idempotent by id. Return True if it was new."""
        if task.id in self._tasks:
            return False
        self._tasks[task.id] = task
        self._status[task.id] = _PENDING
        return True

    def ready(self) -> list[Task]:
        """Pending tasks whose dependencies are all done."""
        out = []
        for tid, task in self._tasks.items():
            if self._status[tid] != _PENDING:
                continue
            if all(self._status.get(d) == _DONE for d in task.deps):
                out.append(task)
        return out

    def mark_running(self, task_id: str) -> None:
        self._status[task_id] = _RUNNING

    def mark_done(self, task_id: str) -> None:
        self._status[task_id] = _DONE

    def is_done(self, task_id: str) -> bool:
        return self._status.get(task_id) == _DONE

    def counts(self) -> dict[str, int]:
        out = {_PENDING: 0, _RUNNING: 0, _DONE: 0}
        for s in self._status.values():
            out[s] = out.get(s, 0) + 1
        return out

    def unfinished(self) -> int:
        return sum(1 for s in self._status.values() if s != _DONE)

    # --- checkpoint -------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "tasks": [self._task_to_dict(t) for t in self._tasks.values()],
            "status": dict(self._status),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TaskGraph":
        tg = cls()
        for td in data.get("tasks", []):
            task = Task(
                id=td["id"],
                capability=td["capability"],
                target=td["target"],
                params=td.get("params", {}),
                tier=td.get("tier", "recon"),
                scope_host=td.get("scope_host"),
                osint=td.get("osint", False),
                deps=tuple(td.get("deps", ())),
                confidence=td.get("confidence", 1.0),
            )
            tg._tasks[task.id] = task
        tg._status = dict(data.get("status", {}))
        return tg

    @staticmethod
    def _task_to_dict(t: Task) -> dict:
        return {
            "id": t.id,
            "capability": t.capability,
            "target": t.target,
            "params": t.params,
            "tier": t.tier,
            "scope_host": t.scope_host,
            "osint": t.osint,
            "deps": list(t.deps),
            "confidence": t.confidence,
        }

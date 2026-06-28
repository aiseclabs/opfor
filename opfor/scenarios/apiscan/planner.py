"""The apiscan planner: one active-check task per target per template.

Deterministic. For every web-app target on the blackboard, it emits one task per
template. The control shell runs them concurrently. Active checks are intrusive
tier, so scope must explicitly permit them, this is not a passive sweep.
"""

from __future__ import annotations

from opfor.agent.planner import Planner
from opfor.engine.graph import SituationGraph
from opfor.engine.tasks import Task


class ApiscanPlanner(Planner):
    def __init__(self, templates: list[dict]) -> None:
        self._templates = templates or []

    def expand(self, graph: SituationGraph) -> list[Task]:
        tasks: list[Task] = []
        for t in graph.targets():
            if t.kind != "webapp":
                continue
            base = t.props.get("url") or f"https://{t.id}/"
            host = t.props.get("host", t.id)
            for tpl in self._templates:
                # A template's type selects the executor: a multi-step jwt flow
                # or the default single request-and-match active check.
                capability = "jwt_attack" if tpl.get("type") == "jwt" else "active_check"
                tasks.append(Task(
                    id=f"check:{t.id}:{tpl['id']}",
                    capability=capability,
                    target=t.id,
                    params={"base_url": base, "template": tpl},
                    tier="intrusive",
                    scope_host=host,
                ))
        return tasks

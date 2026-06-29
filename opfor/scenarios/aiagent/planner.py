"""The aiagent planner. One prompt-injection probe per template per target.

Deterministic and rule-based, like the recon planner: for each AI-agent target it
emits every injection technique from the knowledge file. Intrusive tier, because
sending an adversarial prompt is an active attempt to manipulate the model, so it
runs only inside the campaign's authorization envelope.
"""

from __future__ import annotations

from opfor.agent.planner import Planner
from opfor.engine.graph import SituationGraph
from opfor.engine.tasks import Task


class AiAgentPlanner(Planner):
    def __init__(self, injections: list[dict]) -> None:
        self._injections = injections or []

    def expand(self, graph: SituationGraph) -> list[Task]:
        tasks: list[Task] = []
        for t in graph.targets():
            if t.kind != "ai_agent":
                continue
            base = t.props.get("url") or t.props.get("base_url")
            host = t.props.get("host")
            path = t.props.get("path", "/")
            field = t.props.get("prompt_field", "prompt")
            for tpl in self._injections:
                tasks.append(Task(
                    id=f"inject:{tpl['id']}:{t.id}", capability="prompt_probe", target=t.id,
                    params={"base_url": base, "path": path, "prompt_field": field, "template": tpl},
                    tier="intrusive", scope_host=host, confidence=0.8,
                ))
        return tasks

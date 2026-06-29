"""The mock planner. Read the index, then the admin page once it is unlocked.

Deterministic and graph-driven: the admin read task only appears once a
credential that unlocks the target is in the graph, so the pokeable surface grows
from current state, exactly as the real recon planner does.
"""

from __future__ import annotations

from opfor.agent.planner import Planner
from opfor.engine.graph import SituationGraph
from opfor.engine.tasks import Task


class MockPlanner(Planner):
    def expand(self, graph: SituationGraph) -> list[Task]:
        tasks: list[Task] = []
        creds = graph.entities("credential")
        for t in graph.targets():
            host = t.props.get("host")
            tasks.append(Task(
                id=f"mockread:{t.id}:/", capability="mock_read", target=t.id,
                params={"ref": "/"}, tier="recon", scope_host=host,
            ))
            # The admin page is reachable only after a credential unlocks the target.
            if any(t.id in getattr(c, "unlocks", ()) for c in creds):
                tasks.append(Task(
                    id=f"mockread:{t.id}:/admin", capability="mock_read", target=t.id,
                    params={"ref": "/admin"}, tier="probe", scope_host=host,
                ))
        return tasks

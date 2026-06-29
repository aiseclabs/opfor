"""The web planner. Get the seed paths, then every same-host link discovered.

Graph-driven crawl: it re-emits a get for each seed path and for each crawled
Endpoint entity every round. The task graph dedupes by id, so a path is fetched
once and the crawl converges as new links stop appearing.
"""

from __future__ import annotations

import urllib.parse

from opfor.agent.planner import Planner
from opfor.engine.graph import SituationGraph
from opfor.engine.tasks import Task


class WebPlanner(Planner):
    def expand(self, graph: SituationGraph) -> list[Task]:
        tasks: list[Task] = []
        for t in graph.targets():
            if t.kind != "web_host":
                continue
            host = t.props.get("host")
            for p in t.props.get("paths", ["/"]):
                tasks.append(self._get(t.id, host, p))
        for ep in graph.entities("endpoint"):
            if ep.props.get("source") != "crawl":
                continue
            tasks.append(self._get(ep.props.get("target"), ep.props.get("host"), ep.props.get("path")))
        return tasks

    def _get(self, target_id: str, host: str, path: str) -> Task:
        url = urllib.parse.urljoin(target_id + "/", path.lstrip("/"))
        return Task(
            id=f"webget:{target_id}:{path}", capability="web_get", target=target_id,
            params={"url": url, "path": path}, tier="recon", scope_host=host,
        )

"""The recon planner, a deterministic DAG over the situation graph.

It emits one task per target, gated on graph state, so the pokeable surface grows
live: roots get discovered and swept, names get resolved, live hosts get probed,
services get checked. No batching here, the control shell runs every ready task
concurrently. This is the rule-based planner the evidence supports for recon.
"""

from __future__ import annotations

from opfor.agent.planner import Planner
from opfor.engine.graph import SituationGraph
from opfor.engine.tasks import Task


class ReconPlanner(Planner):
    def __init__(self, checks: list[dict]) -> None:
        self._checks = checks or []

    def expand(self, graph: SituationGraph) -> list[Task]:
        tasks: list[Task] = []

        # Org seeds -> keyword root discovery. Domain roots -> subdomain sweep and
        # certificate pivot. All passive OSINT (recon tier, allowed by default).
        for t in graph.targets():
            if t.kind == "org":
                tasks.append(Task(id=f"rootkw:{t.id}", capability="root_keyword", target=t.id, tier="recon", osint=True, scope_host=t.id))
            if t.kind == "domain":
                tasks.append(Task(id=f"subs:{t.id}", capability="subdomains", target=t.id, tier="recon", osint=True, scope_host=t.id))
                tasks.append(Task(id=f"pivot:{t.id}", capability="root_pivot", target=t.id, tier="recon", osint=True, scope_host=t.id))

        known = self._known_domains(graph)
        hosts = graph.entities("host")
        attempted = {h.props.get("domain") for h in hosts}
        live = {h.props.get("domain") for h in hosts if h.props.get("live")}

        # Resolve every known, not-yet-attempted domain (one task each, concurrent).
        for name in known:
            if name not in attempted:
                tasks.append(Task(id=f"dns:{name}", capability="dns_resolve", target=name, tier="recon", osint=True, scope_host=name))

        # Probe live domains that have no service yet.
        probed = {s.props.get("domain") for s in graph.entities("service")}
        for name, url in known.items():
            if name in live and name not in probed:
                tasks.append(Task(id=f"probe:{name}", capability="http_probe", target=name, params={"url": url}, tier="probe", scope_host=name))

        # One check task per (service, check), plus a favicon task per service.
        for svc in graph.entities("service"):
            if svc.props.get("status") is None:
                continue
            dom = svc.props.get("domain")
            for chk in self._checks:
                tasks.append(Task(
                    id=f"check:{svc.id}:{chk['id']}", capability="http_check", target=dom,
                    params={"url": svc.id, "path": chk.get("path", "/"), "check": chk},
                    tier="probe", scope_host=dom,
                ))
            tasks.append(Task(id=f"favicon:{svc.id}", capability="favicon", target=dom, params={"url": svc.id}, tier="probe", scope_host=dom))
            tasks.append(Task(id=f"fingerprint:{svc.id}", capability="fingerprint", target=dom, params={"url": svc.id}, tier="probe", scope_host=dom))

        return tasks

    def _known_domains(self, graph: SituationGraph) -> dict[str, str]:
        # Confirmed seed roots + subdomains discovered under them. Candidate roots
        # are excluded, they are not expanded until an operator confirms them.
        domains: dict[str, str] = {}
        for t in graph.targets():
            if t.kind == "domain":
                domains[t.id] = t.props.get("url") or f"https://{t.id}/"
        for d in graph.entities("domain"):
            if d.props.get("candidate"):
                continue
            domains[d.id] = d.props.get("url") or f"https://{d.id}/"
        return domains

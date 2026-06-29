"""CORS misconfiguration detection, data-driven over the generic matcher.

A single safe GET carrying a hostile `Origin` header reveals whether a service
reflects an arbitrary origin in `Access-Control-Allow-Origin`. Reflecting an
arbitrary origin lets any site read the response cross-origin; combined with
`Access-Control-Allow-Credentials: true` it exposes authenticated data, the
dangerous case. The attack knowledge lives in these templates, the executor only
sends the request and the generic `_matches` engine judges the headers, so this
adds no CORS-specific logic to any executor.
"""

from __future__ import annotations

from opfor.agent.planner import Planner
from opfor.engine.graph import SituationGraph
from opfor.engine.tasks import Task

# A clearly attacker-controlled origin we never own. If it comes back in
# Access-Control-Allow-Origin, the service reflects arbitrary origins.
_PROBE_ORIGIN = "https://opfor-cors-probe.example"
_PROBE_HOST = "opfor-cors-probe.example"
_ACAO = "Access-Control-Allow-Origin"
_ACAC = "Access-Control-Allow-Credentials"

CORS_TEMPLATES = [
    {
        "id": "cors-reflect-origin-credentials",
        "severity": "high",
        "title": "CORS reflects arbitrary Origin with credentials",
        "request": {"method": "GET", "path": "/", "headers": {"Origin": _PROBE_ORIGIN}},
        "match": {"header_contains": [
            {"name": _ACAO, "value": _PROBE_HOST},
            {"name": _ACAC, "value": "true"},
        ]},
    },
    {
        "id": "cors-reflect-origin",
        "severity": "medium",
        "title": "CORS reflects arbitrary Origin",
        "request": {"method": "GET", "path": "/", "headers": {"Origin": _PROBE_ORIGIN}},
        # Reflection without credentials, so it does not double-fire with the
        # high-severity credentialed case above.
        "match": {
            "header_contains": [{"name": _ACAO, "value": _PROBE_HOST}],
            "header_not_contains": [{"name": _ACAC, "value": "true"}],
        },
    },
]


class CorsPlanner(Planner):
    """One CORS probe per live service. A safe single GET, so probe tier."""

    def __init__(self, templates=None) -> None:
        self._templates = templates if templates is not None else CORS_TEMPLATES

    def expand(self, graph: SituationGraph) -> list[Task]:
        tasks: list[Task] = []
        for svc in graph.entities("service"):
            if svc.props.get("status") is None:
                continue
            host = svc.props.get("domain")
            for tpl in self._templates:
                tasks.append(Task(
                    id=f"cors:{tpl['id']}:{svc.id}",
                    capability="active_check",
                    target=host,
                    params={"base_url": svc.id, "template": tpl},
                    tier="probe",
                    scope_host=host,
                ))
        return tasks

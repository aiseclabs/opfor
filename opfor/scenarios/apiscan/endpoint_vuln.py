"""Generic per-endpoint vulnerability testing, the auto-targeted layer.

Instead of hand-written paths, this tests the Endpoint entities the discovery
layer found: for each endpoint and each parameter, inject a small battery of
generic payloads and look for non-reflective success signals (a file read, a SQL
error, an evaluated template, cloud metadata). The signals are chosen so a mere
reflection of the payload does not trigger a finding; remaining noise is cut by
the model triage stage. This closes the loop: domain -> endpoints -> vulns,
automatically.
"""

from __future__ import annotations

import urllib.parse

from opfor.agent.planner import Planner
from opfor.engine.graph import SituationGraph
from opfor.engine.tasks import Task

# Each probe is a payload plus a matcher whose signal only appears if the attack
# actually worked, never just because the payload was echoed back.
FUZZ_PROBES = [
    {"id": "traversal", "severity": "high", "payload": "/etc/passwd",
     "match": {"body_contains": "root:x:0:0"}},
    {"id": "sqli", "severity": "high", "payload": "'",
     "match": {"body_regex": r"(?i)(sql syntax|syntax error at or near|SQLSTATE|ORA-\d|unterminated quoted|sqlite|psql:)"}},
    {"id": "injection-error", "severity": "medium", "payload": "')]>\"",
     "match": {"body_regex": r"(?i)(NamingException|LDAP: error|XPathException|XPATH syntax)"}},
    {"id": "ssti", "severity": "critical", "payload": "{{1337*1337}}",
     "match": {"body_contains": "1787569"}},
    {"id": "ssrf", "severity": "critical", "payload": "http://169.254.169.254/latest/meta-data/",
     "match": {"body_contains": "ami-id"}},
]
_MAX_TASKS = 400  # safety cap on the fan-out
# Never fuzz endpoints whose name implies a side effect, even on a GET. A generic
# scanner must not send mail, delete data, or spawn processes as a side effect.
_DANGEROUS = ("delete", "email", "send", "spawn", "exec", "terminate", "logout", "/mcp", "subscri")


def _inject_query(path: str, params: list[str], target: str, payload: str) -> str:
    base = path.split("?")[0]
    q = "&".join(
        f"{p}={urllib.parse.quote(payload, safe='')}" if p == target else f"{p}=1"
        for p in params
    )
    return f"{base}?{q}"


class EndpointVulnPlanner(Planner):
    """For each discovered GET endpoint, fuzz each parameter with the probes."""

    def expand(self, graph: SituationGraph) -> list[Task]:
        tasks: list[Task] = []
        for ep in graph.entities("endpoint"):
            if ep.props.get("method") != "GET":
                continue
            path = ep.props.get("path", "/")
            if any(bad in path.lower() for bad in _DANGEROUS):
                continue  # do not fuzz side-effecting endpoints
            host = ep.props.get("host")
            base = f"https://{host}"
            params = ep.props.get("params") or []
            query_params = [p for p in params if "{" + str(p) + "}" not in path]
            for probe in FUZZ_PROBES:
                for p in query_params:
                    inj = _inject_query(path, query_params, p, probe["payload"])
                    tasks.append(self._task(host, base, probe, inj, f"{path}|{p}"))
                if "{" in path:
                    inj = path[: path.index("{")] + urllib.parse.quote(probe["payload"], safe="") + path[path.index("}") + 1:]
                    tasks.append(self._task(host, base, probe, inj, f"{path}|pathparam"))
                if len(tasks) >= _MAX_TASKS:
                    return tasks
        return tasks

    def _task(self, host, base, probe, inj_path, where) -> Task:
        template = {
            "id": f"fuzz-{probe['id']}-{where}",
            "severity": probe["severity"],
            "title": f"{probe['id']} via parameter injection ({where})",
            "request": {"method": "GET", "path": inj_path},
            "match": probe["match"],
        }
        return Task(
            id=f"fuzz:{probe['id']}:{inj_path}",
            capability="active_check",
            target=host,
            params={"base_url": base, "template": template},
            tier="intrusive",
            scope_host=host,
        )

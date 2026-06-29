"""Blind SSRF detection via the out-of-band collaborator.

The existing ssrf probe is response-based (inject a metadata URL, look for the
response to leak it). The blind case has no such tell: the only proof is the
target reaching out. So this injects a unique collaborator URL into url-shaped
parameters and records a candidate; the runner later confirms a candidate only if
that token was actually hit. Evidence-gated: it only targets parameters whose
name matches the ssrf affinity, so it is not blind fuzzing of every input.

The planner needs only the collaborator's base address (read from the graph), and
the executor only sends the request; correlation lives in the runner, which owns
the live collaborator. No scenario-level object needs the per-run listener.
"""

from __future__ import annotations

import secrets

from opfor.agent.planner import Planner
from opfor.engine.graph import SituationGraph
from opfor.engine.tasks import Task
from opfor.model import Fact, Observation
from opfor.plugins.base import Executor
from opfor.scenarios.apiscan.endpoint_vuln import FUZZ_PROBES, _DANGEROUS, _base_url, _inject_query
from opfor.scenarios.apiscan.executors import _do

_SSRF = next(p for p in FUZZ_PROBES if p["id"] == "ssrf")


class BlindSsrfExecutor(Executor):
    capability = "oob_probe"

    def run(self, task, graph) -> Observation:
        r = task.params["request"]
        raw = _do(task.params["base_url"], r["method"], r["path"])
        return Observation(entrypoint_id=task.id, action="oob_probe",
                           raw={"token": task.params["token"], "candidate": task.params["candidate"],
                                "status": raw.get("status")})

    def perceive(self, observation) -> list[Fact]:
        raw = observation.raw
        # No response signal (it is blind); just record the candidate + its token.
        # The runner correlates the token against the collaborator's hits.
        return [Fact(kind="oob-candidate", about=raw["candidate"]["endpoint"],
                     data={"token": raw["token"], **raw["candidate"]})]


class BlindSsrfPlanner(Planner):
    """Inject a collaborator URL into ssrf-affinity params of GET endpoints."""

    def expand(self, graph: SituationGraph) -> list[Task]:
        base = next((f.data.get("base") for f in graph.facts() if f.kind == "collaborator"), None)
        if not base:
            return []  # no collaborator configured, no blind probing
        done = {(f.data.get("endpoint"), f.data.get("param")) for f in graph.facts() if f.kind == "oob-candidate"}
        tasks: list[Task] = []
        for ep in graph.entities("endpoint"):
            method = ep.props.get("method", "GET")
            path = ep.props.get("path", "/")
            if method != "GET" or any(bad in path.lower() for bad in _DANGEROUS):
                continue
            host = ep.props.get("host")
            base_url = _base_url(ep)
            params = [p for p in (ep.props.get("params") or []) if "{" + str(p) + "}" not in path]
            for p in params:
                if not any(a in str(p).lower() for a in _SSRF["affinity"]):
                    continue  # evidence-gated: only url-shaped params
                if (ep.id, p) in done:
                    continue
                token = secrets.token_hex(8)
                inj = _inject_query(path, params, p, f"{base.rstrip('/')}/{token}")
                tasks.append(Task(
                    id=f"oob:ssrf:{ep.id}:{p}", capability="oob_probe", target=host,
                    params={
                        "base_url": base_url, "request": {"method": "GET", "path": inj}, "token": token,
                        "candidate": {"endpoint": ep.id, "param": p, "host": host, "url": base_url + inj},
                    },
                    tier="intrusive", scope_host=host, confidence=0.8,
                ))
        return tasks


def oob_executors() -> dict[str, Executor]:
    return {"oob_probe": BlindSsrfExecutor()}

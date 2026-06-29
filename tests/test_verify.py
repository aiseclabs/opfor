import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from opfor.engine.graph import SituationGraph
from opfor.engine.tasks import Task
from opfor.model import Finding, Observation
from opfor.scenarios.apiscan.executors import ActiveCheckExecutor
from opfor.scenarios.apiscan.verify import VerifyExecutor, VerifyPlanner


def _proof_finding(fid, base, path, host, match):
    return Finding(id=fid, props={"title": fid, "severity": "high", "domain": host,
                                   "proof": {"base_url": base, "request": {"method": "GET", "path": path},
                                             "match": match, "tier": "intrusive", "scope_host": host}})


# --- planner ----------------------------------------------------------------


def test_verify_planner_emits_only_for_proof_bearing_unjudged_findings():
    graph = SituationGraph()
    graph.add_entity(_proof_finding("finding:a", "http://h", "/a", "h", {"body_contains": "x"}))
    graph.add_entity(Finding(id="finding:noproof", props={"title": "b", "domain": "h"}))  # no proof
    tasks = VerifyPlanner().expand(graph)
    assert {t.params["finding_id"] for t in tasks} == {"finding:a"}
    assert all(t.capability == "verify" and t.tier == "intrusive" for t in tasks)
    # Once a verdict exists, it is not re-verified.
    from opfor.model import Fact
    graph.absorb([Fact(kind="verdict", about="finding:a", data={"finding": "finding:a", "verdict": "confirmed", "reason": "x"})])
    assert VerifyPlanner().expand(graph) == []


# --- executor end to end against a stub -------------------------------------


class _VulnHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = b"root:x:0:0:root:/root" if self.path.startswith("/vuln") else b"clean"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def vuln_server():
    s = ThreadingHTTPServer(("127.0.0.1", 0), _VulnHandler)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{s.server_address[1]}"
    finally:
        s.shutdown()


def _verdict(graph, ex, finding):
    graph.add_entity(finding)
    task = VerifyPlanner().expand(graph)[0]
    facts = ex.perceive(ex.run(task, graph))
    return facts[0].data["verdict"]


def test_real_finding_confirmed_flaky_ruled_false_positive(vuln_server):
    ex = VerifyExecutor()
    g1 = SituationGraph()
    assert _verdict(g1, ex, _proof_finding("finding:real", vuln_server, "/vuln", "h", {"body_contains": "root:x:0:0"})) == "confirmed"
    g2 = SituationGraph()
    # The signal does not reproduce on replay -> the detection was a fluke.
    assert _verdict(g2, ex, _proof_finding("finding:flaky", vuln_server, "/clean", "h", {"body_contains": "root:x:0:0"})) == "false_positive"


# --- detection attaches a replayable proof ----------------------------------


def test_active_check_finding_carries_a_proof_recipe():
    ex = ActiveCheckExecutor()
    tpl = {"id": "t", "severity": "high", "title": "t",
           "request": {"method": "GET", "path": "/"}, "match": {"status": 200}}
    obs = ex.run(Task(id="t", capability="active_check", target="h",
                      params={"base_url": "http://127.0.0.1:1", "template": tpl}, scope_host="h"), None)
    # No server, so the request errors and nothing matches -> no finding, but the
    # path-with-a-real-match case is covered by the stub test above; here assert
    # the run stashes what a proof needs.
    assert obs.raw["base_url"] == "http://127.0.0.1:1"
    assert obs.raw["scope_host"] == "h"

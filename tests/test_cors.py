import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from opfor.engine.graph import SituationGraph
from opfor.engine.tasks import Task
from opfor.model import Service
from opfor.scenarios.apiscan.cors import CORS_TEMPLATES, CorsPlanner
from opfor.scenarios.apiscan.executors import ActiveCheckExecutor, _matches

_HIGH = next(t for t in CORS_TEMPLATES if t["severity"] == "high")
_MEDIUM = next(t for t in CORS_TEMPLATES if t["severity"] == "medium")


# --- generic matcher additions ---------------------------------------------


def test_matches_header_contains_list_all_must_hold():
    raw = {"status": 200, "headers": {"A": "x", "B": "y"}, "body": ""}
    assert _matches({"header_contains": [{"name": "A", "value": "x"}, {"name": "B", "value": "y"}]}, raw)
    assert not _matches({"header_contains": [{"name": "A", "value": "x"}, {"name": "B", "value": "z"}]}, raw)


def test_matches_header_not_contains():
    raw = {"status": 200, "headers": {"Access-Control-Allow-Credentials": "true"}, "body": ""}
    assert not _matches({"header_not_contains": [{"name": "Access-Control-Allow-Credentials", "value": "true"}]}, raw)
    raw2 = {"status": 200, "headers": {}, "body": ""}
    assert _matches({"header_not_contains": [{"name": "Access-Control-Allow-Credentials", "value": "true"}]}, raw2)


# --- planner ----------------------------------------------------------------


def test_cors_planner_emits_probe_per_service():
    graph = SituationGraph()
    graph.add_entity(Service(id="https://x.example.com/", props={"domain": "x.example.com", "status": 200}))
    tasks = CorsPlanner().expand(graph)
    assert len(tasks) == len(CORS_TEMPLATES)
    assert all(t.capability == "active_check" and t.tier == "probe" for t in tasks)
    assert all(t.params["template"]["request"]["headers"]["Origin"].startswith("https://opfor-cors-probe") for t in tasks)
    # No service with a status, no probe.
    assert CorsPlanner().expand(SituationGraph()) == []


# --- end to end against a stub ---------------------------------------------


class _CorsHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        origin = self.headers.get("Origin", "")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        if self.path == "/reflect-cred":
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        elif self.path == "/reflect":
            self.send_header("Access-Control-Allow-Origin", origin)
        elif self.path == "/wild":
            self.send_header("Access-Control-Allow-Origin", "*")
        # /safe: no ACAO header at all
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


@pytest.fixture
def cors_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CorsHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()


def _fires(base, template, path):
    tpl = {**template, "request": {**template["request"], "path": path}}
    ex = ActiveCheckExecutor()
    task = Task(id="t", capability="active_check", target="h",
                params={"base_url": base, "template": tpl}, scope_host="h")
    facts = ex.perceive(ex.run(task, None))
    return any(f.kind == "vuln" for f in facts)


def test_cors_high_fires_only_on_reflected_origin_with_credentials(cors_server):
    assert _fires(cors_server, _HIGH, "/reflect-cred") is True
    assert _fires(cors_server, _HIGH, "/reflect") is False  # reflected, but no credentials
    assert _fires(cors_server, _HIGH, "/safe") is False


def test_cors_medium_fires_on_reflection_without_credentials(cors_server):
    assert _fires(cors_server, _MEDIUM, "/reflect") is True
    assert _fires(cors_server, _MEDIUM, "/reflect-cred") is False  # the high case, not double-fired
    assert _fires(cors_server, _MEDIUM, "/safe") is False
    assert _fires(cors_server, _MEDIUM, "/wild") is False  # wildcard is not arbitrary-origin reflection

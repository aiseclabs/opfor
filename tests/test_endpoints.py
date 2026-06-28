import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from opfor.engine.graph import SituationGraph
from opfor.engine.tasks import Task
from opfor.model import Service
from opfor.scenarios.recon.endpoints import (
    ArchiveExecutor,
    EndpointPlanner,
    JsEndpointsExecutor,
    OpenApiExecutor,
)

_SPEC = b'{"paths":{"/api/users":{"get":{"parameters":[{"name":"id"}]}},"/api/login":{"post":{}}}}'
_HTML = b'<html><head><script src="/app.js"></script></head><body>hi</body></html>'
_JS = b'const u=fetch("/api/secret");axios.get("/v1/admin/config");x="/static/img.png";'


class _SurfaceHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path in ("/openapi.json", "/swagger.json"):
            self._send(200, _SPEC, "application/json")
        elif self.path == "/app.js":
            self._send(200, _JS, "application/javascript")
        elif self.path == "/":
            self._send(200, _HTML, "text/html")
        else:
            self._send(404, b"nope")

    def _send(self, status, body, ctype="text/plain"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def surface_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _SurfaceHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()


def _task(cap, base, host="surface.local"):
    return Task(id=cap, capability=cap, target=host, params={"base_url": base, "host": host}, scope_host=host)


def test_openapi_enumerates_endpoints(surface_server):
    ex = OpenApiExecutor()
    facts = ex.perceive(ex.run(_task("openapi_parse", surface_server), None))
    eps = {e.id for f in facts for e in f.yields}
    assert "GET /api/users" in eps and "POST /api/login" in eps


def test_js_extraction_finds_api_paths(surface_server):
    ex = JsEndpointsExecutor()
    facts = ex.perceive(ex.run(_task("js_endpoints", surface_server), None))
    paths = {e.props["path"] for f in facts for e in f.yields}
    assert "/api/secret" in paths and "/v1/admin/config" in paths
    assert "/static/img.png" not in paths  # not an API-shaped path


def test_archive_merges_sources_and_filters_host():
    sources = [("stub", lambda h: ["https://surface.local/api/x", "https://surface.local/api/y", "https://other.com/z"])]
    ex = ArchiveExecutor(sources=sources)
    facts = ex.perceive(ex.run(_task("archive_urls", "https://surface.local"), None))
    paths = {e.props["path"] for f in facts for e in f.yields}
    assert paths == {"/api/x", "/api/y"}


def test_endpoint_vuln_planner_fuzzes_each_param():
    from opfor.model import Endpoint
    from opfor.scenarios.apiscan.endpoint_vuln import EndpointVulnPlanner

    graph = SituationGraph()
    graph.add_entity(Endpoint(id="GET /api/file", props={
        "host": "x.example.com", "method": "GET", "path": "/api/file", "params": ["path"]}))
    tasks = EndpointVulnPlanner().expand(graph)
    assert tasks and all(t.capability == "active_check" and t.tier == "intrusive" for t in tasks)
    trav = [t for t in tasks if "traversal" in t.params["template"]["id"]]
    assert trav and "%2Fetc%2Fpasswd" in trav[0].params["template"]["request"]["path"]


def test_openapi_extracts_body_params_via_ref():
    from opfor.scenarios.recon.endpoints import OpenApiExecutor

    spec = {
        "paths": {"/api/login": {"post": {
            "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Login"}}}}}}},
        "components": {"schemas": {"Login": {"type": "object", "properties": {"user": {}, "pass": {}}}}},
    }
    from opfor.model import Observation as Obs

    ex = OpenApiExecutor()
    # Drive perceive directly off a raw spec, no network.
    facts = ex.perceive(Obs(entrypoint_id="t", action="openapi_parse",
                            raw={"host": "h", "base": "https://h", "spec": spec["paths"],
                                 "schemas": spec["components"]["schemas"]}))
    ep = [e for f in facts for e in f.yields][0]
    assert ep.id == "POST /api/login"
    assert ep.props["body_params"] == ["user", "pass"]


def test_endpoint_vuln_planner_injects_post_body():
    from opfor.model import Endpoint
    from opfor.scenarios.apiscan.endpoint_vuln import EndpointVulnPlanner

    graph = SituationGraph()
    graph.add_entity(Endpoint(id="POST /api/login", props={
        "host": "x.example.com", "method": "POST", "path": "/api/login",
        "url": "http://x.example.com/api/login", "body_params": ["user", "pass"]}))
    tasks = EndpointVulnPlanner().expand(graph)
    assert tasks and all(t.params["template"]["request"]["method"] == "POST" for t in tasks)
    # http-only host -> tested over http, not https.
    assert all(t.params["base_url"] == "http://x.example.com" for t in tasks)
    # The traversal payload lands inside a JSON body field.
    trav = [t for t in tasks if "traversal" in t.params["template"]["id"]]
    import json
    bodies = [json.loads(t.params["template"]["request"]["body"]) for t in trav]
    assert any(b.get("user") == "/etc/passwd" for b in bodies)
    assert any(b.get("pass") == "/etc/passwd" for b in bodies)


def test_endpoint_vuln_planner_skips_post_without_body_fields():
    from opfor.model import Endpoint
    from opfor.scenarios.apiscan.endpoint_vuln import EndpointVulnPlanner

    graph = SituationGraph()
    graph.add_entity(Endpoint(id="POST /api/blind", props={
        "host": "x.example.com", "method": "POST", "path": "/api/blind", "body_params": []}))
    assert EndpointVulnPlanner().expand(graph) == []  # no field names, no blind-guess body


_VULN_SPEC = (b'{"paths":{"/api/read":{"post":{"requestBody":{"content":{"application/json":'
              b'{"schema":{"properties":{"file":{}}}}}}}}}}')


class _PostVulnHandler(BaseHTTPRequestHandler):
    """A POST endpoint that reflects a file read from its JSON body field."""

    def do_GET(self):  # noqa: N802
        if self.path == "/openapi.json":
            self._send(200, _VULN_SPEC, "application/json")
        else:
            self._send(404, b"nope")

    def do_POST(self):  # noqa: N802
        import json as _json
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode("utf-8", "replace")
        try:
            f = _json.loads(body).get("file", "")
        except Exception:
            f = ""
        out = b"root:x:0:0:root:/root:/bin/bash\n" if f == "/etc/passwd" else b"{}"
        self._send(200, out)

    def _send(self, status, body, ctype="text/plain"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def post_vuln_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _PostVulnHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{port}", f"127.0.0.1:{port}"
    finally:
        server.shutdown()


def test_post_body_injection_fires_finding_end_to_end(post_vuln_server):
    from opfor.scenarios.apiscan.endpoint_vuln import EndpointVulnPlanner
    from opfor.scenarios.apiscan.executors import ActiveCheckExecutor
    from opfor.scenarios.recon.endpoints import OpenApiExecutor

    base, host = post_vuln_server
    graph = SituationGraph()
    # 1. discover the POST endpoint and its body field from the spec.
    oa = OpenApiExecutor()
    for f in oa.perceive(oa.run(_task("openapi_parse", base, host=host), None)):
        for e in f.yields:
            graph.add_entity(e)
    eps = {e.id: e for e in graph.entities("endpoint")}
    assert eps["POST /api/read"].props["body_params"] == ["file"]
    # 2. plan body-injection tasks, 3. run them, and confirm traversal fires.
    ac = ActiveCheckExecutor()
    findings = []
    for t in EndpointVulnPlanner().expand(graph):
        for fact in ac.perceive(ac.run(t, graph)):
            findings += list(fact.yields)
    assert any(f.props.get("severity") == "high" and "traversal" in f.id for f in findings)


def test_endpoint_planner_emits_sources_per_service():
    planner = EndpointPlanner()
    graph = SituationGraph()
    graph.add_entity(Service(id="https://x.example.com/", props={"domain": "x.example.com", "status": 200}))
    caps = {t.capability for t in planner.expand(graph)}
    assert caps == {"openapi_parse", "archive_urls", "js_endpoints"}
    # No service with no status, so no tasks.
    assert EndpointPlanner().expand(SituationGraph()) == []

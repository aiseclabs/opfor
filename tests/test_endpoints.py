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


def test_endpoint_planner_emits_sources_per_service():
    planner = EndpointPlanner()
    graph = SituationGraph()
    graph.add_entity(Service(id="https://x.example.com/", props={"domain": "x.example.com", "status": 200}))
    caps = {t.capability for t in planner.expand(graph)}
    assert caps == {"openapi_parse", "archive_urls", "js_endpoints"}
    # No service with no status, so no tasks.
    assert EndpointPlanner().expand(SituationGraph()) == []

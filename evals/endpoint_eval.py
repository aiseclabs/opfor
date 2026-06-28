"""Measure endpoint-discovery recall against a known set, offline.

A stub app exposes endpoints two ways, an OpenAPI spec and a JS bundle. We run
the passive sources and check how many of the known endpoints each recovers. This
is the evidence layer for the interface fanout, like recon_eval is for findings.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from opfor.engine.tasks import Task
from opfor.scenarios.recon.endpoints import JsEndpointsExecutor, OpenApiExecutor

_SPEC = b'{"paths":{"/api/users":{"get":{}},"/api/login":{"post":{}},"/api/orders":{"get":{}}}}'
_HTML = b'<html><head><script src="/app.js"></script></head></html>'
_JS = b'fetch("/api/secret");fetch("/api/orders");axios.get("/v1/admin");'

# What a perfect run should find (spec union js, deduped).
KNOWN = {"GET /api/users", "POST /api/login", "GET /api/orders", "GET /api/secret", "GET /v1/admin"}


class _H(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body, ct = {
            "/openapi.json": (_SPEC, "application/json"),
            "/app.js": (_JS, "application/javascript"),
            "/": (_HTML, "text/html"),
        }.get(self.path, (b"nope", "text/plain"))
        self.send_response(200 if body != b"nope" else 404)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def run_eval() -> dict:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        found: dict[str, set] = {}
        for cap, ex in (("openapi", OpenApiExecutor()), ("js", JsEndpointsExecutor())):
            task = Task(id=cap, capability=cap, target="stub", params={"base_url": base, "host": "stub"}, scope_host="stub")
            facts = ex.perceive(ex.run(task, None))
            found[cap] = {e.id for f in facts for e in f.yields}
    finally:
        server.shutdown()
    merged = set().union(*found.values())
    return {"recall": len(merged & KNOWN) / len(KNOWN), "found": merged & KNOWN, "per_source": found}


def main() -> None:
    m = run_eval()
    print("=== opfor endpoint-discovery recall ===")
    print(f"recall {m['recall']:.2f}  ({len(m['found'])}/{len(KNOWN)} known endpoints)")
    for src, eps in m["per_source"].items():
        print(f"  [{src}] {sorted(e for e in eps if e in KNOWN)}")


if __name__ == "__main__":
    main()

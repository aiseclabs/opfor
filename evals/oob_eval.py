"""Measure blind-SSRF confirmation via the out-of-band collaborator, offline.

A vulnerable endpoint fetches a URL it is given (server-side request forgery); a
safe endpoint ignores it. We inject the collaborator URL, and a candidate is
confirmed only if the target actually called back. This is the deterministic
guard that blind findings are gated on a real out-of-band callback, not guessed.
"""

from __future__ import annotations

import tempfile
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from opfor.engine.collaborator import Collaborator
from opfor.engine.graph import SituationGraph
from opfor.engine.ledger import Ledger
from opfor.engine.state import Workspace
from opfor.model import Endpoint, Fact
from opfor.runner import _correlate_oob
from opfor.scenarios.apiscan.oob import BlindSsrfExecutor, BlindSsrfPlanner


class _Target(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        # /fetch is vulnerable: it fetches whatever url it is handed (SSRF).
        if self.path.startswith("/fetch") and q.get("url"):
            try:
                urllib.request.urlopen(q["url"][0], timeout=3).read()
            except Exception:
                pass
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def run_eval() -> dict:
    collab = Collaborator().start()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Target)
    host = f"127.0.0.1:{server.server_address[1]}"
    base = f"http://{host}/"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        graph = SituationGraph()
        graph.add_entity(Endpoint(id="GET /fetch", props={"host": host, "method": "GET", "path": "/fetch", "params": ["url"], "url": base + "fetch"}))
        graph.add_entity(Endpoint(id="GET /safe", props={"host": host, "method": "GET", "path": "/safe", "params": ["url"], "url": base + "safe"}))
        graph.absorb([Fact(kind="collaborator", about="campaign", data={"base": collab.base_url})])

        ex = BlindSsrfExecutor()
        for task in BlindSsrfPlanner().expand(graph):
            graph.absorb(ex.perceive(ex.run(task, graph)))

        with tempfile.TemporaryDirectory() as d:
            _correlate_oob(graph, collab, Ledger(Workspace(d).ledger_file))
    finally:
        server.shutdown()
        collab.stop()

    confirmed = [f.data["finding"] for f in graph.facts() if f.kind == "verdict" and f.data["verdict"] == "confirmed"]
    candidates = [f.data.get("endpoint") for f in graph.facts() if f.kind == "oob-candidate"]
    return {"confirmed": confirmed, "candidates": candidates}


if __name__ == "__main__":
    m = run_eval()
    print("=== opfor blind-SSRF (out-of-band) ===")
    print("  candidates:", m["candidates"])
    print("  confirmed :", m["confirmed"])

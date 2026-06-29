"""Measure verification-as-currency offline.

A real vulnerability re-proves on replay (its success signal reproduces) and must
be CONFIRMED; a finding whose signal does not reproduce on replay was a fluke and
must be ruled a FALSE POSITIVE; a finding carrying no replayable proof must be
left UNVERIFIABLE. This is the deterministic guard that the verify stage gates
findings on a concrete oracle, not on a model's opinion.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from opfor.engine.graph import SituationGraph
from opfor.engine.tasks import Task
from opfor.model import Finding
from opfor.scenarios.apiscan.verify import VerifyExecutor, VerifyPlanner


class _H(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path.startswith("/vuln"):
            body = b"... root:x:0:0:root:/root:/bin/bash ..."   # signal present, reproduces
        else:
            body = b"nothing to see here"                       # /flaky: signal absent on replay
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _finding(fid: str, base: str, path: str, host: str, proof: bool) -> Finding:
    props = {"title": fid, "severity": "high", "domain": host, "url": base + path}
    if proof:
        props["proof"] = {
            "base_url": base, "request": {"method": "GET", "path": path},
            "match": {"body_contains": "root:x:0:0"}, "tier": "intrusive", "scope_host": host,
        }
    return Finding(id=f"finding:{fid}", props=props)


def run_eval() -> dict:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    host = f"127.0.0.1:{server.server_address[1]}"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        graph = SituationGraph()
        graph.add_entity(_finding("real", base, "/vuln?f=/etc/passwd", host, proof=True))
        graph.add_entity(_finding("flaky", base, "/flaky?f=/etc/passwd", host, proof=True))
        graph.add_entity(_finding("noproof", base, "/x", host, proof=False))

        ex = VerifyExecutor()
        for task in VerifyPlanner().expand(graph):
            graph.absorb(ex.perceive(ex.run(task, graph)))
    finally:
        server.shutdown()

    verdicts = {f.data["finding"]: f.data["verdict"] for f in graph.facts() if f.kind == "verdict"}
    judged = set(verdicts)
    unverifiable = [f.id for f in graph.entities("finding") if f.id not in judged]
    return {"verdicts": verdicts, "unverifiable": unverifiable}


if __name__ == "__main__":
    m = run_eval()
    print("=== opfor verification-as-currency ===")
    for fid, v in sorted(m["verdicts"].items()):
        print(f"  {v:15} {fid}")
    for fid in m["unverifiable"]:
        print(f"  {'unverifiable':15} {fid}")

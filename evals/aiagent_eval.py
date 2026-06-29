"""Measure prompt-injection detection offline.

Two LLM endpoints: a compliant one that obeys injected instructions (and so
emits the canary) and a guarded one that refuses. The compliant endpoint must be
confirmed vulnerable, the guarded one must stay clean. This is the deterministic
guard that an injection is judged by the model actually emitting the canary, not
by the payload being sent.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from opfor.engine.graph import SituationGraph
from opfor.engine.tasks import Task
from opfor.model import Target
from opfor.scenarios.aiagent import _INJECTIONS
from opfor.scenarios.aiagent.executors import PromptProbeExecutor
from opfor.scenarios.aiagent.planner import AiAgentPlanner


def _make_stub(compliant: bool):
    class _LLM(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            n = int(self.headers.get("Content-Length", 0))
            prompt = json.loads(self.rfile.read(n) or b"{}").get("prompt", "")
            if compliant:
                reply = f"Sure, here you go: {prompt}"   # obeys -> echoes the canary
            else:
                reply = "I'm sorry, I can't comply with that request."  # refuses
            body = json.dumps({"completion": reply}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    return _LLM


def _serve(compliant: bool):
    s = ThreadingHTTPServer(("127.0.0.1", 0), _make_stub(compliant))
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s, f"http://127.0.0.1:{s.server_address[1]}/"


def _run(url: str) -> set:
    graph = SituationGraph()
    graph.add_target(Target(id="agent", kind="ai_agent", props={"url": url, "host": "127.0.0.1"}))
    ex = PromptProbeExecutor()
    for task in AiAgentPlanner(_INJECTIONS).expand(graph):
        graph.absorb(ex.perceive(ex.run(task, graph)))
    return {f.data["finding"] for f in graph.facts() if f.kind == "verdict" and f.data["verdict"] == "confirmed"}


def run_eval() -> dict:
    vs, vurl = _serve(True)
    ss, surl = _serve(False)
    try:
        return {"vulnerable_confirmed": len(_run(vurl)), "safe_confirmed": len(_run(surl)), "techniques": len(_INJECTIONS)}
    finally:
        vs.shutdown()
        ss.shutdown()


if __name__ == "__main__":
    m = run_eval()
    print("=== opfor aiagent (prompt injection) ===")
    print(f"  compliant LLM: {m['vulnerable_confirmed']}/{m['techniques']} injections confirmed")
    print(f"  guarded LLM:   {m['safe_confirmed']}/{m['techniques']} confirmed (should be 0)")

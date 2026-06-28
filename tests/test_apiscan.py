"""Deterministic guards for the self-built active-check engine.

The matcher logic is unit-tested directly (no network), and the executor is run
against a tiny inline stub that mimics a couple of vulnerable responses, so the
engine (request building + matching + finding) is covered without depending on a
live external target.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from opfor.engine.tasks import Task
from opfor.scenarios.apiscan.executors import ActiveCheckExecutor, _matches


def test_matcher_conditions():
    raw = {"status": 200, "headers": {"Location": "https://opfor.example/"}, "body": "root:x:0:0:hi"}
    assert _matches({"status": 200, "body_contains": "root:x:0:0"}, raw) is True
    assert _matches({"status": 404}, raw) is False
    assert _matches({"body_contains": ["root:x:0:0", "hi"]}, raw) is True
    assert _matches({"body_contains": "nope"}, raw) is False
    assert _matches({"body_not_contains": "root:x:0:0"}, raw) is False
    assert _matches({"body_regex": r"(?i)ROOT:x"}, raw) is True
    assert _matches({"header_contains": {"name": "Location", "value": "opfor.example"}}, raw) is True
    assert _matches({"header_contains": {"name": "Location", "value": "evil"}}, raw) is False
    # An error response never matches.
    assert _matches({"status": 200}, {"error": "timeout"}) is False


class _StubHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path.startswith("/api/file?path=/etc/passwd"):
            self._send(200, b"root:x:0:0:root:/root:/bin/sh")
        else:
            self._send(404, b"nope")

    def _send(self, status, body):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def apiscan_stub():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _StubHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()


def test_executor_fires_finding_on_vulnerable_response(apiscan_stub):
    lfi = {
        "id": "lfi", "severity": "high", "title": "LFI",
        "request": {"method": "GET", "path": "/api/file?path=/etc/passwd&type=text/plain"},
        "match": {"status": 200, "body_contains": "root:x:0:0"},
    }
    ex = ActiveCheckExecutor()
    task = Task(id="t", capability="active_check", target="stub",
                params={"base_url": apiscan_stub, "template": lfi}, tier="intrusive", scope_host="stub")
    facts = ex.perceive(ex.run(task, None))
    findings = [e for f in facts for e in f.yields]
    assert findings and findings[0].props["severity"] == "high"


def test_executor_clean_on_safe_response(apiscan_stub):
    miss = {
        "id": "lfi", "severity": "high", "title": "LFI",
        "request": {"method": "GET", "path": "/api/file?path=safe.txt"},
        "match": {"status": 200, "body_contains": "root:x:0:0"},
    }
    ex = ActiveCheckExecutor()
    task = Task(id="t", capability="active_check", target="stub",
                params={"base_url": apiscan_stub, "template": miss}, tier="intrusive", scope_host="stub")
    facts = ex.perceive(ex.run(task, None))
    assert facts[0].kind == "check-clean"

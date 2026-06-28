"""Shared fixtures, including a local stub HTTP server for the web hand."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


class _StubHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802, http.server naming
        if self.path == "/":
            body = (
                b'<html><body>'
                b'<a href="/admin">admin</a> '
                b'<a href="/about">about</a> '
                b'<a href="https://example.com/off">offsite</a>'
                b'</body></html>'
            )
            self._respond(200, body, "text/html")
        elif self.path == "/admin":
            self._respond(200, b"admin area")
        elif self.path == "/about":
            self._respond(200, b"about page")
        else:
            self._respond(404, b"not found")

    def _respond(self, status, body, content_type="text/plain"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence the test server
        pass


@pytest.fixture
def stub_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _StubHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()

"""A self-built out-of-band (OOB) collaborator.

Some vulnerabilities are blind: the proof is not in the HTTP response but in the
target reaching back out. Blind SSRF, blind SQLi with a network sink, XXE/RCE
exfil over DNS or HTTP, all confirm by the target calling a URL we control. The
collaborator is that URL: an in-process HTTP listener that records inbound hits
keyed by a unique, unguessable token. A blind probe injects `url_for(token)`; if
that token is later hit, the target made the callback, which is a clean oracle
that the vulnerability is real, the same proof-by-execution idea as the verify
stage, extended to the classes whose signal is out of band.

Self-built, no external service (no Burp Collaborator / interactsh). The listener
binds locally; `public_base` is the externally reachable address a target can
reach (an operator deployment detail, e.g. a public host or an internal IP),
appended with the token.
"""

from __future__ import annotations

import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Collaborator:
    def __init__(self, public_base: str | None = None) -> None:
        self._hits: dict[str, list[dict]] = {}
        self._public_base = public_base
        self._server: ThreadingHTTPServer | None = None
        self._port: int | None = None

    def start(self, host: str = "127.0.0.1", port: int = 0) -> "Collaborator":
        hits = self._hits

        class _H(BaseHTTPRequestHandler):
            def _record(self):
                token = self.path.lstrip("/").split("/", 1)[0].split("?", 1)[0]
                if token:
                    hits.setdefault(token, []).append({"path": self.path, "method": self.command})
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            do_GET = _record
            do_POST = _record

            def log_message(self, *a):
                pass

        self._server = ThreadingHTTPServer((host, port), _H)
        self._port = self._server.server_address[1]
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self

    def register(self, hint: str = "oob") -> str:
        """A fresh unguessable token. Unguessable so a hit proves the target,
        not someone guessing the token."""
        return f"{hint}{secrets.token_hex(8)}"

    @property
    def base_url(self) -> str:
        """The externally reachable base a target should call back to."""
        return self._public_base or f"http://127.0.0.1:{self._port}"

    def url_for(self, token: str) -> str:
        return f"{self.base_url.rstrip('/')}/{token}"

    def was_hit(self, token: str) -> bool:
        return token in self._hits

    def hits(self, token: str) -> list[dict]:
        return list(self._hits.get(token, []))

    @property
    def port(self) -> int | None:
        return self._port

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server = None

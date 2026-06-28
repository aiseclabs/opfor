"""Controlled, offline targets with a known answer key.

Two local servers, started on ephemeral ports, with planted issues so a run can
be scored objectively:

- VULN: real exposures, every planted check should fire (true positives).
- IAP: an identity-aware-proxy style host that answers 200 with an HTML login
  page for every path, including /.env. Nothing should fire here, it is the
  false-positive trap the negative matchers must survive.

Nothing here touches the internet, so the eval is deterministic and free.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# A 200 HTML login page returned for any path, like Google IAP. Contains "=" so a
# naive .env matcher would fire, which is exactly what must NOT happen.
_IAP_BODY = (
    b'<!doctype html><html lang="en"><head><base href="https://accounts.google.com/">'
    b'<title>Sign in</title></head><body>token=abc redirect=/</body></html>'
)


def _vuln_handler():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path == "/":
                self._send(200, b"<html><body>home</body></html>", "text/html")
            elif self.path == "/.git/config":
                self._send(200, b"[core]\n\trepositoryformatversion = 0\n", "text/plain")
            elif self.path == "/.env":
                self._send(200, b"SECRET_KEY=s3cr3t\nDB_URL=postgres://x\n", "text/plain")
            elif self.path == "/swagger.json":
                self._send(200, b'{"swagger":"2.0","paths":{}}', "application/json")
            else:
                self._send(404, b"nope")

        def _send(self, status, body, ctype="text/plain"):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            # Deliberately no HSTS and no CSP headers, so those checks fire.
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    return H


def _iap_handler():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            # Every path, including /.env, returns the same 200 HTML login page.
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(_IAP_BODY)))
            self.end_headers()
            self.wfile.write(_IAP_BODY)

        def log_message(self, *a):
            pass

    return H


# The flag a successful path traversal must leak. Ground truth for the
# exploitation benchmark: if this appears in any response, the exploit worked.
TRAVERSAL_SECRET = "FLAG{opfor-traversal-7f3a}"


def _traversal_handler():
    import urllib.parse

    class H(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            parsed = urllib.parse.urlsplit(self.path)
            if parsed.path != "/download":
                self._send(200, b"<html>file service, use /download?file=</html>", "text/html")
                return
            # The raw, undecoded file value, so an encoded payload is not yet "../".
            raw = ""
            for kv in parsed.query.split("&"):
                if kv.startswith("file="):
                    raw = kv[len("file="):]
            # Naive defense: block a literal ../ in the request. Bypassable only by
            # url-encoding the traversal, which a fixed naive payload will not find.
            if "../" in raw:
                self._send(400, b"blocked: traversal detected")
                return
            decoded = urllib.parse.unquote(raw)
            if "../secret" in decoded:
                self._send(200, TRAVERSAL_SECRET.encode(), "text/plain")
            elif decoded in ("readme.txt", "readme"):
                self._send(200, b"public readme, nothing to see", "text/plain")
            else:
                self._send(404, b"not found")

        def _send(self, status, body, ctype="text/plain"):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    return H


def start(handler) -> tuple[str, ThreadingHTTPServer]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}/", server


def start_vuln() -> tuple[str, ThreadingHTTPServer]:
    return start(_vuln_handler())


def start_iap() -> tuple[str, ThreadingHTTPServer]:
    return start(_iap_handler())


def start_traversal() -> tuple[str, ThreadingHTTPServer]:
    return start(_traversal_handler())


# The answer key: which check ids SHOULD fire on each target. Keyed by a label,
# resolved to the live host at eval time. Anything fired that is not listed is a
# false positive; anything listed but not fired is a false negative.
ANSWER_KEY = {
    "vuln": {
        "git-config-exposed",
        "dotenv-exposed",
        "swagger-exposed",
        "missing-hsts",
        "missing-csp",
    },
    # IAP returns a 200 HTML login page everywhere. The exposure checks must NOT
    # fire (negative matchers). Its login page does lack HSTS/CSP, so those two
    # are legitimately expected, nothing else.
    "iap": {
        "missing-hsts",
        "missing-csp",
    },
}

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from opfor.engine.graph import SituationGraph
from opfor.engine.ledger import Ledger
from opfor.engine.tasks import Task
from opfor.model import Fact
from opfor.report import render
from opfor.scenarios.recon.fingerprints import FingerprintExecutor

_IAP = (b'<!doctype html><html><head><base href="https://accounts.google.com/v3/signin/">'
        b'</head><body>sign in</body></html>')
_S3 = b'<?xml version="1.0"?><ListBucketResult><Name>tss-internal</Name></ListBucketResult>'


class _H(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path.startswith("/iap"):
            body, server = _IAP, "ESF"
        elif self.path.startswith("/s3"):
            body, server = _S3, "AmazonS3"
        else:
            body, server = b"plain app", "nginx"
        self.send_response(200)
        self.send_header("Server", server)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def fp_server():
    s = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{s.server_address[1]}"
    finally:
        s.shutdown()


def _run(base, path):
    ex = FingerprintExecutor()
    task = Task(id="fp", capability="fingerprint", target="h", params={"url": base + path},
                tier="probe", scope_host="h")
    return ex.perceive(ex.run(task, None))


def test_iap_gateway_is_classified_not_a_finding(fp_server):
    facts = _run(fp_server, "/iap")
    cls = [f for f in facts if f.kind == "classification"]
    assert cls and cls[0].data["id"] == "google-iap-gateway"
    assert cls[0].data["category"] == "gateway"
    assert not any(f.yields for f in facts)  # a gateway is not a finding


def test_s3_listing_emits_finding_with_proof(fp_server):
    facts = _run(fp_server, "/s3")
    findings = [e for f in facts for e in f.yields]
    assert findings and findings[0].props["title"].startswith("S3 bucket")
    # The finding carries a replayable proof so the verify stage can re-prove it.
    proof = findings[0].props["proof"]
    assert proof["match"] == {"body_contains": "<ListBucketResult"}


def test_plain_service_matches_nothing(fp_server):
    facts = _run(fp_server, "/plain")
    assert all(f.kind == "fingerprint-clean" for f in facts)


def test_report_lists_hardened_gateways(tmp_path):
    g = SituationGraph()
    g.absorb([Fact(kind="classification", about="https://x/", data={
        "service": "https://x/", "domain": "x", "id": "google-iap-gateway",
        "label": "Google IAP gateway, no unauthenticated surface", "category": "gateway"})])
    out = render(g, Ledger(tmp_path / "ledger.jsonl"), stopped_reason="done")
    assert "Hardened (behind an auth gateway)" in out
    assert "https://x/" in out

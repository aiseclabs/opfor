"""Replay a recorded product cassette through opfor's real probe pipeline to the host profile.

A cassette is the full set of HTTP responses opfor's probe drew from a real product instance, so
replaying it drives the actual capabilities, the redirect handling, the paths probed, the evidence
building, and the fingerprint, against recorded reality rather than a hand-typed string, fidelity
by full-response replay. The identify seam is the deterministic fingerprint only, no model, so the
backtest measures the shipped table itself, and the triage model is a stub that mints nothing since
only the host_profile fact is read.
"""

from __future__ import annotations

import json
from pathlib import Path

from opfor.core import Budget, MockProvider, Node, Scope, World
from opfor.core.engine import run as engine_run
from opfor.scenarios.attacksurface import build
from opfor.scenarios.attacksurface.hostnames import HostScope
from opfor.scenarios.attacksurface.types import Org
from opfor.scenarios.attacksurface.assets.domain import KNOWLEDGE
from opfor.scenarios.attacksurface.assets.domain.sources import fingerprint, load_fingerprints

_TABLE = load_fingerprints(KNOWLEDGE / "fingerprints.yaml")


def _fingerprint_only(evidence: str) -> dict:
    """The identify seam for a backtest, the deterministic table with no model fallback, so a
    result is the table's own verdict on the recorded evidence, not a model's."""
    return fingerprint(evidence, _TABLE)


def load_cassette(path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _seams(cassette: dict) -> dict:
    host = cassette["host"]
    resolved = cassette.get("resolved", {"resolvable": True, "addresses": ("127.0.0.1",), "cnames": ()})
    root = cassette["root"]
    fetch = cassette.get("fetch", {})
    docs = cassette.get("docs", {})

    def enumerate_fn(domain):
        return set()

    def resolve_fn(name):
        return resolved if name == host else {"resolvable": False, "addresses": (), "cnames": ()}

    def probe_fn(name, addresses=()):
        if name == host:
            return root
        return {"alive": False, "status": None, "url": "", "server": "", "title": "", "body": "",
                "location": "", "headers": (), "reason": "no-public-address"}

    def fetch_fn(name, addresses, path):
        return fetch.get(path, {"status": 404, "url": f"https://{name}{path}", "content_type": "",
                                "server": "", "title": "", "body": "", "location": "", "reason": ""})

    def fetch_doc_fn(name, path):
        return docs.get(path, {"status": None, "content_type": "", "text": ""})

    def introspect_fn(name, path="/graphql"):
        return None

    def wayback_fn(h):
        return set()

    def probe_url_fn(url):
        return {"status": 404, "url": url, "content_type": "", "body": "", "reason": ""}

    def dns_fn(d):
        return {"spf": (), "dmarc": "", "caa": (), "dnssec": False}

    def tls_fn(name, addresses=()):
        return {"host": name, "reachable": False, "reason": "no-tls", "valid": False,
                "validity_error": "", "not_after": "", "days_to_expiry": None,
                "protocol": "", "cipher": ""}

    return dict(enumerate_fn=enumerate_fn, resolve_fn=resolve_fn, probe_fn=probe_fn,
                fetch_fn=fetch_fn, fetch_doc_fn=fetch_doc_fn, introspect_fn=introspect_fn,
                wayback_fn=wayback_fn, probe_url_fn=probe_url_fn, dns_fn=dns_fn, tls_fn=tls_fn)


def profile_for(cassette: dict):
    """Run opfor's probe pipeline over a cassette and return the host_profile payload, or None when
    the host was not profiled. The identify seam is the deterministic fingerprint, so the product
    and version are the table's verdict on the recorded evidence."""
    host = cassette["host"]
    scenario = build(identify_fn=_fingerprint_only, cve_fn=None,
                     provider=MockProvider(responses=['{"findings": []}'] * 50),
                     **_seams(cassette))
    world = World()
    world.add(Node(id="org:target", type="org", payload=Org(name="target", domains=(host,))))
    engine_run(scenario, world,
               scope=Scope(max_tier="recon", matcher=HostScope(hosts=(host,))),
               budget=Budget(5000))
    prof = world.latest("host_profile", f"domain:{host}")
    return prof.payload if prof is not None else None

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
from opfor.scenarios.attacksurface.assets.domain import PATHS
from opfor.scenarios.attacksurface.assets.domain.sources.observations import (
    EmailPosture,
    Liveness,
    Resolution,
    Response,
    TLSReport,
)
from opfor.scenarios.attacksurface.assets.domain.fingerprint import fingerprint, load_services

_TABLE = load_services(PATHS.services)


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
        if name != host:
            return Resolution(resolvable=False)
        return Resolution(resolvable=resolved.get("resolvable", True),
                          addresses=tuple(resolved.get("addresses", ())),
                          cnames=tuple(resolved.get("cnames", ())))

    def probe_fn(name, addresses=()):
        if name != host:
            return Liveness(alive=False, reason="no-public-address")
        return Liveness(alive=root.get("alive", False), status=root.get("status"),
                        url=root.get("url", ""), server=root.get("server", ""),
                        title=root.get("title", ""), body=root.get("body", ""),
                        location=root.get("location", ""),
                        headers=tuple(tuple(h) for h in root.get("headers", ())),
                        reason=root.get("reason", ""))

    def fetch_fn(name, addresses, path):
        d = fetch.get(path)
        if d is None:
            return Response(status=404, url=f"https://{name}{path}")
        return Response(status=d.get("status"), url=d.get("url", f"https://{name}{path}"),
                        content_type=d.get("content_type", ""), server=d.get("server", ""),
                        title=d.get("title", ""), body=d.get("body", ""),
                        location=d.get("location", ""), reason=d.get("reason", ""))

    def fetch_doc_fn(name, path):
        d = docs.get(path)
        if d is None:
            return Response(status=None)
        return Response(status=d.get("status"), content_type=d.get("content_type", ""),
                        body=d.get("text", d.get("body", "")))

    def introspect_fn(name, path="/graphql"):
        return None

    def wayback_fn(h):
        return set()

    def probe_url_fn(url):
        return Response(status=404, url=url)

    def dns_fn(d):
        return EmailPosture()

    def tls_fn(name, addresses=()):
        return TLSReport(reachable=False, reason="no-tls")

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

"""Drive opfor's real engine over a recorded cassette, the shared spine both offline tiers run on.

A cassette is the full set of HTTP responses opfor's probe drew from a real product instance, so
replaying it drives the actual capabilities, the redirect handling, the paths probed, the evidence
building, the fingerprint, the CVE lookup, and the deterministic minting, against recorded reality
rather than a hand-typed string. The DNS and HTTP seams replay the cassette, the CVE seam replays
the cassette's recorded database response, and the triage provider is a stub that mints nothing on
its own, so the only findings a run produces are the deterministic ones, the known-vulnerability
findings the CVE chain mints, which is exactly what the offline tier grades.

The identify seam is a caller's choice: the offline tier forces the deterministic fingerprint table
so a run is the table's own verdict, the live tier passes None so the composed seam falls through to
the model on an off-table host. This module holds the replay, not the policy, so both tiers share
one driver.
"""

from __future__ import annotations

import json
from pathlib import Path

from opfor.core import Budget, MockProvider, Node, Scope, World
from opfor.core.engine import run as engine_run
from opfor.core.result import Report
from opfor.scenarios.attacksurface import build
from opfor.scenarios.attacksurface.assets.domain import PATHS
from opfor.scenarios.attacksurface.assets.domain.fingerprint import fingerprint, load_products
from opfor.scenarios.attacksurface.assets.domain.hostnames import HostScope
from opfor.scenarios.attacksurface.assets.domain.seed import Org
from opfor.scenarios.attacksurface.assets.domain.sources.observations import (
    Liveness,
    Resolution,
    Response,
)

_TABLE = load_products(PATHS.products)


def load_cassette(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def fingerprint_only(evidence: str) -> dict:
    """The identify seam for the offline tier, the deterministic table with no model fallback, so a
    result is the table's own verdict on the recorded evidence, not a model's."""
    return fingerprint(evidence, _TABLE)


def _cve_replay(payload):
    """Build a CVE seam that replays a cassette's recorded database response, so the CVE chain is
    graded on opfor's own routing and minting rather than on a live database that drifts. The rows
    are returned verbatim for any lookup, since a cassette is one host, so the recorded response is
    that host's response. An absent payload replays an empty result, a clean negative that still
    exercises the product to cve_scan routing."""
    rows = [dict(r) for r in (payload or [])]

    def cve_fn(product, version, cpe):
        return rows

    return cve_fn


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

    def fetch_fn(name, addresses, path, *, body_limit=None):
        # The cassette already holds each body at the size it was recorded, a version endpoint at
        # the larger cap, so the replay honors body_limit implicitly and need not truncate it again.
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

    return dict(enumerate_fn=enumerate_fn, resolve_fn=resolve_fn, probe_fn=probe_fn,
                fetch_fn=fetch_fn, fetch_doc_fn=fetch_doc_fn, introspect_fn=introspect_fn,
                wayback_fn=wayback_fn)


def run_cassette(cassette: dict, *, identify_fn=fingerprint_only) -> tuple[World, Report]:
    """Replay a cassette through the real engine to the terminal phase and return the world and the
    report. The CVE seam replays the cassette's recorded `cve` response, always wired so an
    identified host runs the full product to cve_scan to minting chain, and the triage provider is a
    stub, so the only findings are the deterministic ones. `identify_fn` defaults to the
    deterministic table, the offline tier's choice, and a caller passes None for the live model."""
    host = cassette["host"]
    scenario = build(identify_fn=identify_fn, cve_fn=_cve_replay(cassette.get("cve")), osv_fn=None,
                     provider=MockProvider(responses=['{"findings": []}'] * 50),
                     **_seams(cassette))
    world = World()
    world.add(Node(id="org:target", type="org", payload=Org(name="target", domains=(host,))))
    report = engine_run(scenario, world,
                        scope=Scope(max_tier="recon", matcher=HostScope(hosts=(host,))),
                        budget=Budget(5000))
    return world, report


def profile_for(cassette: dict):
    """The host_profile payload a cassette replays to, or None when the host was not profiled. Kept
    as a thin read over `run_cassette` for the identity scorer and the direct profile tests."""
    host = cassette["host"]
    world, _report = run_cassette(cassette)
    prof = world.latest("host_profile", f"domain:{host}")
    return prof.payload if prof is not None else None

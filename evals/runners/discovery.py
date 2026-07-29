"""Tier A discovery runner: replay recorded passive-source bytes through the real subdomain union
and the real `EnumerateSubdomains` capability, so the recall link is graded end to end on frozen
real responses rather than a hand-typed set.

This is the MAP-phase subdomain step, the second link of the domain scan. Its recall rests on two
things a synthetic fixture can drift away from: each source parser reading a real response shape
correctly, and the union folding those sources into one set that drops a sibling registrable
domain, drops the apex, and collapses a wildcard to its base. So the runner feeds the recorded
certspotter and wayback bytes to the real parsers, folds them through the real `subdomains` union,
and runs the real capability over the result. The paging walk and the all-sources-dead fail-loud
path are exercised by `tests/scenarios/attacksurface/test_domain_enumeration.py`, not here, since
those are logic paths a synthetic fixture covers as well, and this tier adds only what frozen real
bytes catch, a parser or fold regression.

The keyed sources are neutralized for the run so a developer with a VirusTotal or OTX key in the
environment grades the same deterministic union as CI, invariant 4.
"""

from __future__ import annotations

import json
from contextlib import contextmanager

from opfor.core import Node, Task, World
from opfor.scenarios.attacksurface.assets.domain.capabilities.discovery import EnumerateSubdomains
from opfor.scenarios.attacksurface.assets.domain.sources import enumeration as en
from opfor.scenarios.attacksurface.assets.domain.sources import keys
from opfor.scenarios.attacksurface.assets.domain.types import DomainData


def _replayed(parser, recorded, payload_key: str):
    """A source function that parses the recorded bytes rather than fetching, carrying the recorded
    truncation flag so the union folds the same signal a live fetch would have."""

    def source(domain: str) -> en.Enumeration:
        result = en.Enumeration(parser(recorded[payload_key], domain))
        result.truncated = bool(recorded.get("truncated", False))
        return result

    return source


@contextmanager
def _sources_replayed(sources: dict):
    """Swap each recorded passive source for a parser over its frozen bytes, and neutralize the
    keyed sources, so the real union runs deterministically over the cassette. Restored on exit so
    the swap never leaks into another run."""
    saved = {
        "certspotter_subdomains": en.certspotter_subdomains,
        "wayback_subdomains": en.wayback_subdomains,
        "virustotal_key": keys.virustotal_key,
        "otx_key": keys.otx_key,
    }
    if "certspotter" in sources:
        en.certspotter_subdomains = _replayed(en.subdomains_from_certspotter,
                                              sources["certspotter"], "records")
    if "wayback" in sources:
        en.wayback_subdomains = _replayed(en.subdomains_from_wayback, sources["wayback"], "rows")
    keys.virustotal_key = lambda: ""
    keys.otx_key = lambda: ""
    try:
        yield
    finally:
        en.certspotter_subdomains = saved["certspotter_subdomains"]
        en.wayback_subdomains = saved["wayback_subdomains"]
        keys.virustotal_key = saved["virustotal_key"]
        keys.otx_key = saved["otx_key"]


def run_discovery(bench):
    """Run the real subdomain union and capability over a discovery benchmark's recorded sources,
    returning the capability outcome the scorer grades."""
    data = json.loads(bench.evidence.read_text(encoding="utf-8"))
    root = str(data["root"]).strip().lower()
    with _sources_replayed(data.get("sources") or {}):
        world = World()
        world.add(Node(id=f"domain:{root}", type="domain",
                       payload=DomainData(name=root, root=root, source="hint")))
        return EnumerateSubdomains(en.subdomains).run(
            Task(capability="domain_subdomains", node=f"domain:{root}"), world)

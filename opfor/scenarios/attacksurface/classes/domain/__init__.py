"""The domain asset class: an org's hint roots and inventory hosts to a ranked web surface.

It owns the passive discovery and evidence pivots, the resolution and probing pipeline, and
the triage knowledge that judges a web surface, the classes of finding, the exposure clues,
and the takeover signatures, all under its `knowledge` tree. So it declares a knowledge
directory the scenario's triage reads.
"""

from __future__ import annotations

from pathlib import Path

from opfor.scenarios.attacksurface.classes import ClassBundle
from opfor.scenarios.attacksurface.classes.domain import planner
from opfor.scenarios.attacksurface.classes.domain.capabilities import (
    CveScan,
    DiscoverDomains,
    DomainPivot,
    DomainRegistrant,
    Endpoints,
    ExpandSpec,
    GraphQLIntrospect,
    HarvestPaths,
    HTTPDomain,
    ResolveDomain,
    SourceMapScan,
    Subdomains,
)

KNOWLEDGE = Path(__file__).resolve().parent / "knowledge"


def assemble(*, enumerate_fn, pivot_fn, resolve_fn, probe_fn, fetch_fn, fetch_doc_fn,
             introspect_fn, wayback_fn, reverse_whois_fn=None,
             identify_fn=None, cve_fn=None) -> ClassBundle:
    """The domain class's contribution. The seams are the passive and active sources,
    injected so a test drives the class with fixtures. The registrant pivot rides only when
    its keyed source is wired, so a keyless run omits it rather than failing per root. The
    CVE scan rides only when both its identify and lookup seams are wired."""
    capabilities = [
        DiscoverDomains(),
        DomainPivot(pivot_fn),
        Subdomains(enumerate_fn),
        ResolveDomain(resolve_fn),
        HTTPDomain(probe_fn),
        HarvestPaths(fetch_fn, fetch_doc_fn, wayback_fn),
        Endpoints(fetch_fn),
        ExpandSpec(fetch_doc_fn),
        GraphQLIntrospect(introspect_fn),
        SourceMapScan(fetch_doc_fn),
    ]
    if reverse_whois_fn is not None:
        capabilities.append(DomainRegistrant(reverse_whois_fn))
    if identify_fn is not None and cve_fn is not None:
        capabilities.append(CveScan(identify_fn, cve_fn))
    return ClassBundle(
        name="domain",
        capabilities=tuple(capabilities),
        map_rules=tuple(planner.map_rules(with_registrant=reverse_whois_fn is not None)),
        enrich_rules=tuple(planner.enrich_rules(
            with_cve=identify_fn is not None and cve_fn is not None)),
        knowledge_dir=KNOWLEDGE,
    )

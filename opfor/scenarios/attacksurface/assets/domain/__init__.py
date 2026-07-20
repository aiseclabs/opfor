"""The domain asset class: an org's hint roots and inventory hosts to a ranked web surface.

It owns the passive discovery and evidence pivots, the resolution and probing pipeline, and
the triage knowledge that judges a web surface, the classes of finding, the exposure clues,
and the takeover signatures, all under its `knowledge` tree. So it declares a knowledge
directory the scenario's triage reads.
"""

from __future__ import annotations

from pathlib import Path

from opfor.scenarios.attacksurface.assets import ClassBundle
from opfor.scenarios.attacksurface.assets.domain import planner
from opfor.scenarios.attacksurface.assets.domain.sources import fingerprint, load_fingerprints
from opfor.scenarios.attacksurface.assets.domain.sources.profile import (
    classify_frameworks,
    classify_fronting,
    load_frameworks,
    load_fronting,
)
from opfor.scenarios.attacksurface.assets.domain.capabilities import (
    BackupScan,
    BucketScan,
    CVELookup,
    DeclaredRoots,
    DiscoverDomains,
    DNSEmailSecurity,
    DomainPivot,
    DomainRegistrant,
    Endpoints,
    PermuteSubdomains,
    PortServices,
    ExpandSpec,
    GraphQLIntrospect,
    ProbeSpec,
    ProfileHost,
    HarvestPaths,
    HTTPDomain,
    PermutePaths,
    RedirectRoots,
    ResolveDomain,
    SecretScan,
    SourceMapScan,
    Subdomains,
    TLSSecurity,
)

KNOWLEDGE = Path(__file__).resolve().parent / "knowledge"


def assemble(*, enumerate_fn, pivot_fn, resolve_fn, probe_fn, fetch_fn, fetch_doc_fn,
             introspect_fn, wayback_fn, probe_url_fn, dns_fn, tls_fn, ports_fn,
             reverse_whois_fn=None, identify_fn=None, cve_fn=None) -> ClassBundle:
    """The domain class's contribution. The seams are the passive and active sources,
    injected so a test drives the class with fixtures. The registrant pivot rides only when
    its keyed source is wired, so a keyless run omits it rather than failing per root. The
    CVE scan rides only when both its identify and lookup seams are wired."""
    capabilities = [
        DiscoverDomains(),
        DomainPivot(pivot_fn),
        DeclaredRoots(dns_fn),
        RedirectRoots(resolve_fn, probe_fn),
        Subdomains(enumerate_fn),
        PermuteSubdomains(resolve_fn),
        ResolveDomain(resolve_fn),
        DNSEmailSecurity(dns_fn),
        HTTPDomain(probe_fn),
        TLSSecurity(tls_fn),
        PortServices(ports_fn),
        HarvestPaths(fetch_fn, fetch_doc_fn, wayback_fn),
        PermutePaths(),
        Endpoints(fetch_fn),
        ExpandSpec(fetch_doc_fn),
        ProbeSpec(fetch_fn),
        GraphQLIntrospect(introspect_fn),
        SourceMapScan(fetch_doc_fn),
        SecretScan(fetch_doc_fn),
        BackupScan(fetch_fn),
        BucketScan(probe_url_fn),
    ]
    if reverse_whois_fn is not None:
        capabilities.append(DomainRegistrant(reverse_whois_fn))
    # A deterministic fingerprint table identifies a known product without a model call, with
    # the exact version a version header carries. It wraps the injected model identify seam, so
    # the seam tries the table first and falls to the model on a miss, and a thin or stale table
    # identifies less rather than wrong. The table is the class's own knowledge, loaded here at
    # assemble time. An empty table leaves the seam pure model, so a missing file is no regression.
    fingerprints = load_fingerprints(KNOWLEDGE / "fingerprints.yaml")
    if identify_fn is not None and fingerprints:
        model_identify = identify_fn

        def identify_fn(evidence):
            return fingerprint(evidence, fingerprints) or model_identify(evidence)
    # ProfileHost is the single place a host's identity is derived: the product via the composed
    # identify seam, and the front-end frameworks and fronting via the injected deterministic
    # classifiers, so the capability reads no knowledge. It emits one host_profile fact the CVE
    # lookup and the report both read, so identity survives a CVE-lookup failure and exists even
    # with no CVE seam wired. Frameworks and fronting are deterministic, so it runs with or without
    # a model identify seam.
    frameworks_table = load_frameworks(KNOWLEDGE / "frameworks.yaml")
    fronting_table = load_fronting(KNOWLEDGE / "fronting.yaml")

    def framework_fn(http):
        return classify_frameworks(http, frameworks_table)

    def fronting_fn(name, resolved, http):
        return classify_fronting(name, resolved, http, fronting_table)

    capabilities.append(ProfileHost(identify_fn, framework_fn, fronting_fn))
    if cve_fn is not None:
        capabilities.append(CVELookup(cve_fn))
    # The plan config is loaded here, at assemble time, not at planner import, so the content
    # root stays swappable and importing the class triggers no file IO.
    config = planner.load_plan_config(KNOWLEDGE)
    return ClassBundle(
        name="domain",
        capabilities=tuple(capabilities),
        map_rules=tuple(planner.map_rules(with_registrant=reverse_whois_fn is not None)),
        enrich_rules=tuple(planner.enrich_rules(
            config, with_profile=True, with_cve=cve_fn is not None)),
        knowledge_dir=KNOWLEDGE,
    )

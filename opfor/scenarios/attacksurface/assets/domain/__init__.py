"""The domain asset class: an org's hint roots and inventory hosts to a ranked web surface.

It owns the passive discovery and evidence pivots, the resolution and probing pipeline, and
the triage knowledge that judges a web surface, the classes of finding, the exposure clues,
and the takeover signatures, all under its `knowledge` tree. So it declares a knowledge
directory the scenario's triage reads.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from opfor.scenarios.attacksurface.assets import ClassBundle
from opfor.scenarios.attacksurface.assets.domain import planner
from opfor.scenarios.attacksurface.assets.domain.sources import (
    fingerprint,
    load_services,
    service_version_paths,
)
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
    DiscoverDomains,
    DNSEmailSecurity,
    Endpoints,
    PermuteSubdomains,
    ExpandSpec,
    GraphQLIntrospect,
    ProbeSpec,
    ProfileHost,
    HarvestPaths,
    HTTPDomain,
    PermutePaths,
    ResolveDomain,
    SecretScan,
    SourceMapScan,
    Subdomains,
    TLSSecurity,
)

KNOWLEDGE = Path(__file__).resolve().parent / "knowledge"


def assemble(*, enumerate_fn, resolve_fn, probe_fn, fetch_fn, fetch_doc_fn,
             introspect_fn, wayback_fn, probe_url_fn, dns_fn, tls_fn,
             identify_fn=None, cve_fn=None) -> ClassBundle:
    """The domain class's contribution. The seams are the passive and active sources, injected so
    a test drives the class with fixtures. The run maps exactly the operator's seed roots and
    expands each to its subdomains, no root discovery beyond the seed. The CVE lookup rides only
    when its lookup seam is wired."""
    capabilities = [
        DiscoverDomains(),
        Subdomains(enumerate_fn),
        PermuteSubdomains(resolve_fn),
        ResolveDomain(resolve_fn),
        DNSEmailSecurity(dns_fn),
        HTTPDomain(probe_fn),
        TLSSecurity(tls_fn),
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
    # The per-service knowledge units identify a known service without a model call, with the
    # exact version a version header or endpoint carries. They wrap the injected model identify
    # seam, so the seam tries the services first and falls to the model on a miss, and a thin or
    # stale set identifies less rather than wrong. They are the class's own knowledge, loaded here
    # at assemble time. An empty set leaves the seam pure model, so a missing tree is no regression.
    fingerprints = load_services(KNOWLEDGE / "services")
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
    # root stays swappable and importing the class triggers no file IO. The services' own version
    # endpoints join the generic probe paths, so a service versioned only at an endpoint is probed
    # there without that endpoint being a global path, its knowledge stays in the service's unit.
    config = planner.load_plan_config(KNOWLEDGE)
    extra_paths = tuple(p for p in service_version_paths(fingerprints) if p not in config.probe_paths)
    if extra_paths:
        config = replace(config, probe_paths=config.probe_paths + extra_paths)
    return ClassBundle(
        name="domain",
        capabilities=tuple(capabilities),
        map_rules=tuple(planner.map_rules()),
        enrich_rules=tuple(planner.enrich_rules(
            config, with_profile=True, with_cve=cve_fn is not None)),
        knowledge_dir=KNOWLEDGE,
    )

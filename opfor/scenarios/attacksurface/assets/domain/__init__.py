"""The domain asset class: an org's hint roots and inventory hosts to a ranked web surface.

It owns the passive discovery and evidence pivots, the resolution and probing pipeline, and
the triage knowledge that judges a web surface, the classes of finding, the exposure clues,
and the takeover signatures, all under its `knowledge` tree. So it declares a knowledge
directory the scenario's triage reads.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path

from opfor.scenarios.attacksurface.assets.base import ClassBundle
from opfor.scenarios.attacksurface.lifecycle.grounding import ReproductionRecipe, load_reproductions
from opfor.scenarios.attacksurface.assets.domain import nuclei
from opfor.scenarios.attacksurface.assets.domain import planner
from opfor.scenarios.attacksurface.assets.domain.fingerprint import (
    fingerprint,
    load_products,
    product_probe_paths,
)
from opfor.scenarios.attacksurface.assets.domain.classifiers import (
    classify_frameworks,
    load_frameworks,
)
from opfor.scenarios.attacksurface.assets.domain.capabilities.specs import (
    SPEC_PROBE_PATHS,
    GRAPHQL_PROBE_PATHS,
)
from opfor.scenarios.attacksurface.assets.domain.capabilities.http import DISCLOSURE_PROBE_PATHS
from opfor.scenarios.attacksurface.assets.domain.capabilities import (
    BackupScan,
    BucketScan,
    CVELookup,
    DiscoverDomains,
    ProbeDNSEmailPosture,
    ProbeEndpoints,
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
    EnumerateSubdomains,
    ProbeTLSPosture,
)

KNOWLEDGE = Path(__file__).resolve().parent / "knowledge"


@dataclass(frozen=True, kw_only=True)
class KnowledgePaths:
    """The fixed layout of the domain class's knowledge tree, resolved to absolute paths, so the
    tree's shape lives in one contract rather than scattered `root / "fingerprints" / "products"`
    conventions that drift as the tree grows. A finding file under `findings` carries both the
    model-read judgment prose and, in its frontmatter, the deterministic payloads that class
    surfaces, so a concept is one file. `fingerprints` holds the technology identification data."""

    root: Path
    products: Path
    frameworks: Path
    findings: Path
    nuclei: Path

    @classmethod
    def under(cls, root: Path) -> "KnowledgePaths":
        fingerprints = root / "fingerprints"
        return cls(root=root, products=fingerprints / "products",
                   frameworks=fingerprints / "frameworks", findings=root / "findings",
                   nuclei=root / "nuclei")


PATHS = KnowledgePaths.under(KNOWLEDGE)


def _template_recipes(nuclei_dir) -> tuple[ReproductionRecipe, ...]:
    """Reproduction recipes derived from the vendored Nuclei templates, so the recipe data is a real
    published template opfor consumes, not a hand-typed one. A read-only template grounds a GET
    recipe replayed at the intrusive tier, a state-changing template grounds a recipe carrying its
    write method and body, replayed only at the exploit tier under the explicit authorization. A
    template's matcher summary rides as the recipe's expectation, so the confirm judge sees the
    template's full fire condition. Only the first candidate request is grounded for now, the replay
    runs one request, iterating a template's request list is a later increment."""
    supported, _unsupported = nuclei.load_templates(nuclei_dir)
    recipes: list[ReproductionRecipe] = []
    for template in supported:
        request = template.requests[0]
        path = request.paths[0].replace("{{BaseURL}}", "").replace("{{RootURL}}", "")
        recipes.append(ReproductionRecipe(
            cve=template.cve, method=request.method, path=path,
            expect=nuclei.matcher_summary(request), body=request.body))
    return tuple(recipes)


def _template_chains(nuclei_dir) -> tuple:
    """Multi-step exploit chains derived from the vendored Nuclei templates, a raw request chain
    with extractors and a dsl matcher the single-request consumer cannot express. Each is driven
    whole at the exploit tier under the explicit authorization. A template that is not a raw chain
    is left to the single-request consumer, so the two never ground the same CVE twice."""
    from opfor.scenarios.attacksurface.assets.domain import nuclei_chain
    chains = []
    for path in sorted(Path(nuclei_dir).glob("*.yaml")):
        result = nuclei_chain.parse_chain(path.read_text(encoding="utf-8"))
        if isinstance(result, nuclei_chain.ChainTemplate):
            chains.append(result)
    return tuple(chains)


def assemble(*, enumerate_fn, resolve_fn, probe_fn, fetch_fn, fetch_doc_fn,
             introspect_fn, wayback_fn, probe_url_fn, dns_fn, tls_fn,
             identify_fn=None, cve_fn=None) -> ClassBundle:
    """The domain class's contribution. The seams are the passive and active sources, injected so
    a test drives the class with fixtures. The run maps exactly the operator's seed roots and
    expands each to its subdomains, no root discovery beyond the seed. The CVE lookup rides only
    when its lookup seam is wired."""
    # The per-product knowledge units are loaded once here, so their own paths are read both as the
    # probe's version endpoints and as the identify seam's markers below.
    fingerprints = load_products(PATHS.products)
    capabilities = [
        DiscoverDomains(),
        EnumerateSubdomains(enumerate_fn),
        PermuteSubdomains(resolve_fn),
        ResolveDomain(resolve_fn),
        ProbeDNSEmailPosture(dns_fn),
        HTTPDomain(probe_fn),
        ProbeTLSPosture(tls_fn),
        HarvestPaths(fetch_fn, fetch_doc_fn, wayback_fn),
        PermutePaths(),
        ProbeEndpoints(fetch_fn, version_paths=product_probe_paths(fingerprints)),
        ExpandSpec(fetch_doc_fn),
        ProbeSpec(fetch_fn),
        GraphQLIntrospect(introspect_fn),
        SourceMapScan(fetch_doc_fn),
        SecretScan(fetch_doc_fn),
        BackupScan(fetch_fn),
        BucketScan(probe_url_fn),
    ]
    # The per-product knowledge units identify a known product without a model call, with the
    # exact version a version header or endpoint carries. They wrap the injected model identify
    # seam, so the seam tries the products first and falls to the model on a miss, and a thin or
    # stale set identifies less rather than wrong. They are the class's own knowledge, loaded here
    # at assemble time. An empty set leaves the seam pure model, so a missing tree is no regression.
    if identify_fn is not None and fingerprints:
        model_identify = identify_fn

        def identify_fn(evidence):
            return fingerprint(evidence, fingerprints) or model_identify(evidence)
    # ProfileHost is the single place a host's identity is derived: the product via the composed
    # identify seam, and the front-end frameworks via the injected deterministic classifier, so the
    # capability reads no knowledge. It emits one host_profile fact the CVE lookup and the report
    # both read, so identity survives a CVE-lookup failure and exists even with no CVE seam wired.
    # Framework classification is deterministic, so it runs with or without a model identify seam.
    frameworks_table = load_frameworks(PATHS.frameworks)

    def framework_fn(http):
        return classify_frameworks(http, frameworks_table)

    capabilities.append(ProfileHost(identify_fn, framework_fn,
                                    version_paths=product_probe_paths(fingerprints)))
    if cve_fn is not None:
        capabilities.append(CVELookup(cve_fn))
    # The plan config is loaded here, at assemble time, not at planner import, so the content root
    # stays swappable and importing the class triggers no file IO. The probe set is composed from
    # the owners of each path rather than one global guessed list: the products' own identification
    # and version endpoints, the spec-discovery locations owned by ExpandSpec, the GraphQL endpoint
    # owned by the introspector, and the disclosure files owned by the harvester.
    config = planner.load_plan_config(PATHS)
    owned = (product_probe_paths(fingerprints) + SPEC_PROBE_PATHS
             + GRAPHQL_PROBE_PATHS + DISCLOSURE_PROBE_PATHS)
    extra_paths = tuple(p for p in owned if p not in config.probe_paths)
    if extra_paths:
        config = replace(config, probe_paths=config.probe_paths + extra_paths)
    return ClassBundle(
        name=planner.CLASS,
        capabilities=tuple(capabilities),
        map_rules=tuple(planner.map_rules()),
        enrich_rules=tuple(planner.enrich_rules(
            config, with_profile=True, with_cve=cve_fn is not None)),
        knowledge_dir=KNOWLEDGE,
        reproductions=load_reproductions(PATHS.products) + _template_recipes(PATHS.nuclei),
        chains=_template_chains(PATHS.nuclei),
    )

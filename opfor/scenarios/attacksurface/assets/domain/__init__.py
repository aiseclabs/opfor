"""The domain asset class: an org's hint roots and inventory hosts to a ranked web surface.

It owns the passive discovery and label permutation, the resolution and probing pipeline, and
the triage knowledge that judges a web surface, the classes of finding, the exposure clues,
and the takeover signatures, all under its `knowledge` tree. So it declares a knowledge
directory the scenario's triage reads.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path

from opfor.core import Node, Phase, Provider, RuleSet, Scenario, World, make_provider
from opfor.core import default_model, role_model, triage_mode
from opfor.scenarios.attacksurface.assets.base import ClassBundle
from opfor.scenarios.attacksurface.assets.domain.grounding import (
    FindingGrounder,
    ReproductionRecipe,
    load_reproductions,
)
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
    CVELookup,
    DiscoverDomains,
    ProbeEndpoints,
    PermuteSubdomains,
    ExpandSpec,
    GraphQLIntrospect,
    ProbeSpec,
    ProfileHost,
    HarvestPaths,
    ProbeDomainHTTP,
    PermutePaths,
    ResolveDomain,
    EnumerateSubdomains,
)
from opfor.scenarios.attacksurface.assets.domain import identify
from opfor.scenarios.attacksurface.assets.domain import sources as domain_src
from opfor.scenarios.attacksurface.assets.domain.hostnames import HostScope
from opfor.scenarios.attacksurface.assets.domain.triage import SurfaceTriage
from opfor.scenarios.attacksurface.assets.domain.report import report_view
from opfor.scenarios.attacksurface.assets.domain.seed import Org

# The scenario a domain run belongs to. Both asset classes build a scenario under this one name,
# the shell dispatches by asset class, so the report and the registry name the scenario, not a class.
SCENARIO = "attacksurface"

KNOWLEDGE = Path(__file__).resolve().parent / "knowledge"


@dataclass(frozen=True, kw_only=True)
class KnowledgePaths:
    """The fixed layout of the domain class's knowledge tree, resolved to absolute paths, so the
    tree's shape lives in one contract rather than scattered `root / "technologies" / "products"`
    conventions that drift as the tree grows. A finding file under `findings` carries both the
    model-read judgment prose and, in its frontmatter, the deterministic payloads that class
    surfaces, so a concept is one file. `technologies` holds the technology identification data,
    the same directory name the chain class uses for its role fingerprints."""

    root: Path
    products: Path
    frameworks: Path
    findings: Path
    nuclei: Path

    @classmethod
    def under(cls, root: Path) -> "KnowledgePaths":
        technologies = root / "technologies"
        return cls(root=root, products=technologies / "products",
                   frameworks=technologies / "frameworks", findings=root / "findings",
                   nuclei=root / "nuclei")


PATHS = KnowledgePaths.under(KNOWLEDGE)


def _template_recipes(nuclei_dir) -> tuple[ReproductionRecipe, ...]:
    """Reproduction recipes derived from the vendored Nuclei templates, so the recipe data is a real
    published template opfor consumes, not a hand-typed one. A read-only template grounds a GET
    recipe, a state-changing template grounds a recipe carrying its write method and body. Every
    candidate path, the request headers, and the matcher set ride into the recipe, so the generated
    PoC checks all of a CVE's endpoints and decides PASS or FAIL by the template's own fire
    condition rather than a paraphrase. A template's matcher summary rides as the recipe's prose
    expectation. Only the first request block is grounded for now, a template with more than one
    request block is a later increment."""
    supported, _unsupported = nuclei.load_templates(nuclei_dir)
    recipes: list[ReproductionRecipe] = []
    for template in supported:
        request = template.requests[0]
        paths = tuple(p.replace("{{BaseURL}}", "").replace("{{RootURL}}", "") for p in request.paths)
        recipes.append(ReproductionRecipe(
            cve=template.cve, method=request.method, paths=paths,
            expect=nuclei.matcher_summary(request), headers=request.headers,
            body=request.body, matchers=request.matchers,
            matchers_condition=request.matchers_condition))
    return tuple(recipes)


def assemble(*, enumerate_fn, resolve_fn, probe_fn, fetch_fn, fetch_doc_fn,
             introspect_fn, wayback_fn,
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
        ProbeDomainHTTP(probe_fn),
        HarvestPaths(fetch_fn, fetch_doc_fn, wayback_fn),
        PermutePaths(),
        ProbeEndpoints(fetch_fn, version_paths=product_probe_paths(fingerprints)),
        ExpandSpec(fetch_doc_fn),
        ProbeSpec(fetch_fn),
        GraphQLIntrospect(introspect_fn),
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
        capabilities=tuple(capabilities),
        map_rules=tuple(planner.map_rules()),
        enrich_rules=tuple(planner.enrich_rules(
            config, with_profile=True, with_cve=cve_fn is not None)),
        knowledge_dir=KNOWLEDGE,
        reproductions=load_reproductions(PATHS.products) + _template_recipes(PATHS.nuclei),
    )


def _payloads() -> dict[str, type]:
    """The class's payload dataclasses keyed by class name, collected by introspection so a new
    payload type is registered by defining it, not by editing a hand list. A durable checkpoint
    rebuilds the world's typed payloads from this map."""
    from dataclasses import is_dataclass
    from importlib import import_module

    # Import the submodule through import_module, since this package defines a `seed` function
    # that shadows the `seed` submodule as a package attribute, so a plain `from . import seed`
    # would bind the function and drop the seed node's payload.
    domain_seed = import_module("opfor.scenarios.attacksurface.assets.domain.seed")
    domain_types = import_module("opfor.scenarios.attacksurface.assets.domain.types")

    registry: dict[str, type] = {}
    for module in (domain_seed, domain_types):
        for name, obj in vars(module).items():
            if isinstance(obj, type) and is_dataclass(obj):
                registry[name] = obj
    return registry


def _resolve_provider(provider, model):
    """The triage provider and model, built from the environment when the caller passed none,
    keyless on the operator's Claude Code subscription by default. The model falls back to the
    env-backed default. Read at build so a changed environment is seen, see the registry."""
    if provider is None:
        provider = make_provider()
    return provider, model or default_model()


def _adversarial_roles(provider, model, challenger, challenger_model, judge, judge_model):
    """The challenger and judge roles for triage. In adversarial mode the challenger refutes
    each finding and a judge breaks the tie, so a false positive must survive a skeptic. The
    roles reuse the base provider by default with a per-role model override, and a caller may
    inject its own. Standard mode leaves them off, the recall-safe single-model default."""
    if triage_mode() != "adversarial":
        return challenger, challenger_model, judge, judge_model
    if challenger is None:
        challenger, challenger_model = provider, role_model("challenger", model)
    if judge is None:
        judge, judge_model = provider, role_model("judge", model)
    return challenger, challenger_model, judge, judge_model


def build(
    *,
    enumerate_fn=domain_src.subdomains,
    resolve_fn=domain_src.resolve_host,
    probe_fn=domain_src.http_probe,
    fetch_fn=domain_src.fetch_url,
    fetch_doc_fn=domain_src.fetch_document,
    introspect_fn=domain_src.graphql_introspect,
    wayback_fn=domain_src.wayback_paths,
    identify_fn=None,
    cve_fn=domain_src.nvd_cves,
    provider: Provider | None = None,
    model: str | None = None,
    challenger: Provider | None = None,
    challenger_model: str | None = None,
    judge: Provider | None = None,
    judge_model: str | None = None,
) -> Scenario:
    """Assemble the domain-class scenario. Triage and the CVE-scan identify are model-backed,
    built from the provider the environment selects, keyless on the operator's Claude Code
    subscription by default, and a test injects its own. Triage runs an adversarial challenger and
    judge when OPFOR_TRIAGE_MODE is adversarial, standard single-model otherwise."""
    provider, model = _resolve_provider(provider, model)

    # The CVE scan identifies a host's product with the model, then looks the version up. The
    # identify seam is model-backed, wired from the same provider by default, so the capability
    # holds no model, and a test injects its own fake. The lookup seam is the NVD source. Both
    # together turn the scan on, see the class assemble.
    if identify_fn is None:
        def identify_fn(evidence):
            return identify.identify_service(provider, model, evidence)

    challenger, challenger_model, judge, judge_model = _adversarial_roles(
        provider, model, challenger, challenger_model, judge, judge_model)

    bundle = assemble(enumerate_fn=enumerate_fn, resolve_fn=resolve_fn, probe_fn=probe_fn,
                      fetch_fn=fetch_fn, fetch_doc_fn=fetch_doc_fn, introspect_fn=introspect_fn,
                      wayback_fn=wayback_fn, identify_fn=identify_fn, cve_fn=cve_fn)
    knowledge_dirs = [bundle.knowledge_dir] if bundle.knowledge_dir else []
    reproductions = bundle.reproductions
    rules = {Phase.MAP: list(bundle.map_rules), Phase.ENRICH: list(bundle.enrich_rules)}

    return Scenario(
        name=SCENARIO,
        content_root=Path(__file__).resolve().parent,
        capabilities=bundle.capabilities,
        planner=RuleSet(rules),
        triage=SurfaceTriage(knowledge_dirs, provider=provider, model=model,
                             challenger=challenger, challenger_model=challenger_model,
                             judge=judge, judge_model=judge_model,
                             recipe_cves=tuple(r.cve for r in reproductions)),
        grounding=FindingGrounder(reproductions=reproductions),
        payloads=_payloads(),
        scope_matcher=HostScope.from_dict,
        terminal=Phase.TRIAGE,
    )


def seed(name: str, *, domains=(), hosts=()) -> World:
    """Build the seed world for a run, an `Org` node carrying the hint roots and the known
    inventory hosts. This is the entry a run path uses to turn operator input, whether typed
    on the command line or loaded from a seed file, into the world the engine drives."""
    world = World()
    world.add(Node(id=f"org:{name}", type="org",
                   payload=Org(name=name, domains=tuple(domains), hosts=tuple(hosts))))
    return world


def prepare_run(*, name="", roots=(), roots_file="", hosts=(), hosts_file="",
                tier="recon", authorized=False, reproduce=False, confirm=False):
    """Adapt a CLI run request into the domain class's seeded world, scope, and built scenario.
    A flag wins over the environment, roots and hosts fold to registrable roots the same way a
    seed file does, and the scope hosts are the roots plus each host's registrable root so a
    subdomain is authorized by its root. The class is recon-only, so the reproduce and confirm
    flags do not raise the terminal, it always stops at TRIAGE. It raises on an empty seed, an
    empty run is an operator error not a result."""
    from opfor.core import Scope
    from opfor.scenarios.attacksurface.assets.domain import config
    from opfor.scenarios.attacksurface.assets.domain.hostnames import HostScope, registrable_root
    from opfor.scenarios.attacksurface.assets.domain.sources import (
        hosts_from_file, hosts_from_values, roots_from_file, roots_from_values)

    # A flag value folds the same way a seed-file line does, so `--root www.example.com` enumerates
    # the registrable root example.com rather than a name the certificate logs do not index.
    rts = list(roots_from_values(roots))
    roots_path = roots_file or config.roots_file()
    if roots_path:
        rts += roots_from_file(roots_path)
    hst = list(hosts_from_values(hosts))
    hosts_path = hosts_file or config.hosts_file()
    if hosts_path:
        hst += hosts_from_file(hosts_path)
    rts = tuple(dict.fromkeys(rts))
    hst = tuple(dict.fromkeys(hst))
    if not rts and not hst:
        raise ValueError("no seed given, pass --root or --roots, or --host or --hosts, "
                         "or set OPFOR_ROOTS_FILE or OPFOR_HOSTS_FILE")
    target = name or config.target_name() or (rts[0] if rts else registrable_root(hst[0]))
    scope_hosts = tuple(dict.fromkeys(list(rts) + [registrable_root(h) for h in hst]))
    world = seed(target, domains=rts, hosts=hst)
    scope = Scope(max_tier=tier, matcher=HostScope(hosts=scope_hosts), authorized=authorized)
    return target, world, scope, build()

"""The attack-surface scenario: from a root domain to a judged surface and an accurate PoC.

The seed is an `Org`, the operator's root domains and known hosts. MAP discovers the
subdomains under each root, ENRICH identifies what each host is and analyzes its service
state, the interfaces it exposes, the product it runs and that product's CVEs, and TRIAGE
judges the findings and writes an accurate proof of concept for each. The PoC is written,
never sent, so this scenario reports a surface, it never touches a target beyond recon.

It reads public sources and probes only the domains scope authorizes, and it stops at
TRIAGE, a declared finish line, so a full run is a closed run. There is no intrusive tier and
no request is ever sent to a target for reproduction. Every source is an injected seam, so a
test drives the whole scenario with fixtures. `build` wires the real seams and composes the
capabilities, the planner rules, and the knowledge its triage reads, all in one place.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path

from opfor.core import Node, Phase, Provider, RuleSet, Scenario, World, make_provider
from opfor.core import default_model
from opfor.core import role_model, triage_mode
from opfor.scenarios.attacksurface import identify
from opfor.scenarios.attacksurface import nuclei
from opfor.scenarios.attacksurface import planner
from opfor.scenarios.attacksurface import sources as domain_src
from opfor.scenarios.attacksurface.capabilities import (
    CVELookup,
    DiscoverDomains,
    EnumerateSubdomains,
    ExpandSpec,
    GraphQLIntrospect,
    HarvestPaths,
    PermutePaths,
    PermuteSubdomains,
    ProbeDomainHTTP,
    ProbeEndpoints,
    ProbeSpec,
    ProfileHost,
    ResolveDomain,
)
from opfor.scenarios.attacksurface.capabilities.http import DISCLOSURE_PROBE_PATHS
from opfor.scenarios.attacksurface.capabilities.specs import GRAPHQL_PROBE_PATHS, SPEC_PROBE_PATHS
from opfor.scenarios.attacksurface.classifiers import classify_frameworks, load_frameworks
from opfor.scenarios.attacksurface.fingerprint import (
    fingerprint,
    load_products,
    product_probe_paths,
)
from opfor.scenarios.attacksurface.hostnames import HostScope
from opfor.scenarios.attacksurface.lifecycle.grounding import (
    FindingGrounder,
    ReproductionRecipe,
    load_reproductions,
)
from opfor.scenarios.attacksurface.lifecycle.triage import SurfaceTriage
from opfor.scenarios.attacksurface.report import report_view
from opfor.scenarios.attacksurface.seed import Org

NAME = "attacksurface"

KNOWLEDGE = Path(__file__).resolve().parent / "knowledge"


@dataclass(frozen=True, kw_only=True)
class KnowledgePaths:
    """The fixed layout of the knowledge tree, resolved to absolute paths, so the tree's shape
    lives in one contract rather than scattered `root / "fingerprints" / "products"` conventions
    that drift as the tree grows. A finding file under `findings` carries both the model-read
    judgment prose and, in its frontmatter, the deterministic payloads that class surfaces, so a
    concept is one file. `fingerprints` holds the technology identification data."""

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


def _payloads() -> dict[str, type]:
    """The scenario's payload dataclasses keyed by class name, collected from the modules that
    define them, so a durable checkpoint can rebuild the world's typed payloads. Collected by
    introspection rather than a hand list, so a new payload type is registered by defining it,
    not by editing this map."""
    from dataclasses import is_dataclass
    from opfor.scenarios.attacksurface import seed as surface_seed
    from opfor.scenarios.attacksurface import types as domain_types

    registry: dict[str, type] = {}
    for module in (surface_seed, domain_types):
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
    """The challenger and judge roles for triage. In adversarial mode a challenger refutes
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
    # Triage is model-backed. Build the provider and model the environment selects, keyless on
    # the operator's Claude Code subscription by default, and let a test inject its own.
    provider, model = _resolve_provider(provider, model)

    # The CVE scan identifies a host's product with the model, then looks the version up. The
    # identify seam is model-backed, wired from the same provider by default, so the capability
    # holds no model, and a test injects its own fake. The lookup seam is the NVD source.
    if identify_fn is None:
        def identify_fn(evidence):
            return identify.identify_service(provider, model, evidence)

    challenger, challenger_model, judge, judge_model = _adversarial_roles(
        provider, model, challenger, challenger_model, judge, judge_model)

    # The seams are the passive and active sources, injected so a test drives the scenario with
    # fixtures. The run maps exactly the operator's seed roots and expands each to its subdomains,
    # no root discovery beyond the seed. The CVE lookup rides only when its lookup seam is wired.
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
    # The per-product knowledge units identify a known product without a model call, with the exact
    # version a version header or endpoint carries. They wrap the injected model identify seam, so
    # the seam tries the products first and falls to the model on a miss, and a thin or stale set
    # identifies less rather than wrong. They are the scenario's own knowledge, loaded here at build
    # time. An empty set leaves the seam pure model, so a missing tree is no regression.
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

    # The plan config is loaded here, at build time, not at planner import, so the content root
    # stays swappable and importing the module triggers no file IO. The probe set is composed from
    # the owners of each path rather than one global guessed list: the products' own identification
    # and version endpoints, the spec-discovery locations owned by ExpandSpec, the GraphQL endpoint
    # owned by the introspector, and the disclosure files owned by the harvester.
    config = planner.load_plan_config(PATHS)
    owned = (product_probe_paths(fingerprints) + SPEC_PROBE_PATHS
             + GRAPHQL_PROBE_PATHS + DISCLOSURE_PROBE_PATHS)
    extra_paths = tuple(p for p in owned if p not in config.probe_paths)
    if extra_paths:
        config = replace(config, probe_paths=config.probe_paths + extra_paths)

    reproductions = load_reproductions(PATHS.products) + _template_recipes(PATHS.nuclei)
    rules = {
        Phase.MAP: list(planner.map_rules()),
        Phase.ENRICH: list(planner.enrich_rules(
            config, with_profile=True, with_cve=cve_fn is not None)),
    }

    return Scenario(
        name=NAME,
        content_root=Path(__file__).resolve().parent,
        capabilities=tuple(capabilities),
        planner=RuleSet(rules),
        triage=SurfaceTriage([KNOWLEDGE], provider=provider, model=model,
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
                tier="recon", authorized=False):
    """Adapt a CLI run request into this scenario's seeded world, scope, and built scenario, so
    the generic CLI holds no attack-surface specifics and a new scenario becomes runnable by
    registering its own adapter, not by editing the CLI. Returns the resolved target name, the
    seed world, the scope, and the scenario. A flag wins over the environment, roots and hosts
    fold to registrable roots the same way a seed file does, and the scope hosts are the roots
    plus each host's registrable root so a subdomain is authorized by its root. It raises on an
    empty seed, an empty run is an operator error not a result."""
    from opfor.core import Scope
    from opfor.scenarios.attacksurface import config
    from opfor.scenarios.attacksurface.hostnames import HostScope, registrable_root
    from opfor.scenarios.attacksurface.sources import (
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
    scenario = build()
    return target, world, scope, scenario

"""The attack-surface scenario: from a root domain to a judged surface and an accurate PoC.

The seed is an `Org`, the operator's root domains and known hosts. MAP discovers the
subdomains under each root, ENRICH identifies what each host is and analyzes its service
state, the interfaces it exposes, the product it runs and that product's CVEs, and TRIAGE
judges the findings and writes an accurate proof of concept for each. The PoC is written,
never sent, so this scenario reports a surface, it never touches a target beyond recon.

The surface is worked one asset class at a time, a self-contained plugin under `assets/`
that owns its payloads, capabilities, rules, and knowledge. Today that is `domain`. This
module names the classes the scenario is built from and concatenates their contributions,
the one place that lists them, the way the registry is the one place that lists scenarios.
Adding a class is a new package there plus one line here, never an edit to an existing class.

It reads public sources and probes only the domains scope authorizes, and it stops at
TRIAGE, a declared finish line, so a full run is a closed run. There is no intrusive tier and
no request is ever sent to a target for reproduction. Every source is an injected seam, so a
test drives the whole scenario with fixtures. `build` wires the real seams.
"""

from __future__ import annotations

from pathlib import Path

from opfor.core import Node, Phase, Provider, RuleSet, Scenario, World, make_provider
from opfor.core import default_model
from opfor.core import role_model, triage_mode
from opfor.scenarios.attacksurface.assets import domain
from opfor.scenarios.attacksurface.hostnames import HostScope
from opfor.scenarios.attacksurface.assets.domain import identify
from opfor.scenarios.attacksurface.assets.domain import sources as domain_src
from opfor.scenarios.attacksurface.lifecycle.triage import SurfaceTriage
from opfor.scenarios.attacksurface.lifecycle.grounding import FindingGrounder
from opfor.scenarios.attacksurface.report import report_view
from opfor.scenarios.attacksurface.seed import Org

NAME = "attacksurface"


def _payloads() -> dict[str, type]:
    """The scenario's payload dataclasses keyed by class name, collected from the modules that
    define them, so a durable checkpoint can rebuild the world's typed payloads. Collected by
    introspection rather than a hand list, so a new payload type is registered by defining it,
    not by editing this map."""
    from dataclasses import is_dataclass
    from opfor.scenarios.attacksurface import seed as surface_seed
    from opfor.scenarios.attacksurface.assets.domain import types as domain_types

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

    # The CVE scan identifies a host's product with the model, then looks the version up.
    # The identify seam is model-backed, wired from the same provider by default, so the
    # capability holds no model, and a test injects its own fake. The lookup seam is the
    # NVD source. Both together turn the scan on, see the domain class assemble.
    if identify_fn is None:
        def identify_fn(evidence):
            return identify.identify_service(provider, model, evidence)

    challenger, challenger_model, judge, judge_model = _adversarial_roles(
        provider, model, challenger, challenger_model, judge, judge_model)

    # The asset classes the scenario is built from. Each returns a bundle, its capabilities
    # and rules plus the knowledge its triage reads. The scenario concatenates them and
    # names no class-internal type, so a class is swapped or added without touching this loop.
    bundles = [
        domain.assemble(enumerate_fn=enumerate_fn, resolve_fn=resolve_fn,
                        probe_fn=probe_fn, fetch_fn=fetch_fn, fetch_doc_fn=fetch_doc_fn,
                        introspect_fn=introspect_fn, wayback_fn=wayback_fn,
                        identify_fn=identify_fn, cve_fn=cve_fn),
    ]
    capabilities = tuple(cap for bundle in bundles for cap in bundle.capabilities)
    map_rules = [rule for bundle in bundles for rule in bundle.map_rules]
    enrich_rules = [rule for bundle in bundles for rule in bundle.enrich_rules]
    knowledge_dirs = [bundle.knowledge_dir for bundle in bundles if bundle.knowledge_dir]
    reproductions = tuple(r for bundle in bundles for r in bundle.reproductions)

    rules = {Phase.MAP: map_rules, Phase.ENRICH: enrich_rules}

    return Scenario(
        name=NAME,
        content_root=Path(__file__).resolve().parent,
        capabilities=capabilities,
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
    scenario = build()
    return target, world, scope, scenario

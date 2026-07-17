"""The attack-surface scenario: from an org name to a ranked map of its assets.

The seed is an `Org`, an organization the operator names, such as a company. The run
discovers assets under it across classes and triages the whole into a ranked inventory.
The operator restricts to a class with `Org.classes`, empty runs them all.

An asset class is a self-contained plugin under `assets/`, and it owns its payloads,
capabilities, rules, and knowledge. This module names the classes the scenario is built
from and concatenates their contributions, the one place that lists them, the way the
registry is the one place that lists scenarios. Adding a class is a new package there plus
one line here, never an edit to an existing class.

It reads public sources and probes only the domains scope authorizes, and it stops at
TRIAGE, a declared finish line, so a full run is a closed run. Every source is an injected
seam, so a test drives the whole scenario with fixtures. `build` wires the real seams.
"""

from __future__ import annotations

from pathlib import Path

from opfor.core import Node, Phase, Provider, RuleSet, Scenario, World, make_provider
from opfor.core.providers.factory import default_model, role_model, triage_mode
from opfor.scenarios.attacksurface import config
from opfor.scenarios.attacksurface.assets import domain, github
from opfor.scenarios.attacksurface.assets.domain import identify
from opfor.scenarios.attacksurface.assets.domain import sources as domain_src
from opfor.scenarios.attacksurface.assets.github import sources as github_src
from opfor.scenarios.attacksurface.triage import SurfaceTriage
from opfor.scenarios.attacksurface.confirm import ConfirmTriage
from opfor.scenarios.attacksurface.grounding import FindingGrounder
from opfor.scenarios.attacksurface.reproduce import ReproduceFinding, reproduce_rule
from opfor.scenarios.attacksurface.types import Org

NAME = "attacksurface"


def _payloads() -> dict[str, type]:
    """The scenario's payload dataclasses keyed by class name, collected from the modules that
    define them, so a durable checkpoint can rebuild the world's typed payloads. Collected by
    introspection rather than a hand list, so a new payload type is registered by defining it,
    not by editing this map."""
    from dataclasses import is_dataclass
    from opfor.scenarios.attacksurface import reproduce, types as surface_types
    from opfor.scenarios.attacksurface.assets.domain import types as domain_types
    from opfor.scenarios.attacksurface.assets.github import types as github_types

    registry: dict[str, type] = {}
    for module in (surface_types, domain_types, github_types, reproduce):
        for name, obj in vars(module).items():
            if isinstance(obj, type) and is_dataclass(obj):
                registry[name] = obj
    return registry

# Sentinel so build can tell an unset reverse-WHOIS seam from one a caller passed, even
# a fake in a test, and default the real seam to on only when a provider key is set.
_DEFAULT = object()


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


def _terminal_phase(*, reproduce, confirm):
    """The phase a run stops at, TRIAGE by default. Confirm regrades findings against the
    reproduction receipts the EXPLOIT phase records, so confirm implies reproduce and rises to
    CONFIRM, while a bare reproduce rises to EXPLOIT for the read-only replay."""
    if confirm:
        return Phase.CONFIRM
    if reproduce:
        return Phase.EXPLOIT
    return Phase.TRIAGE


def build(
    *,
    search_fn=github_src.search_orgs,
    repos_fn=github_src.org_repos,
    enumerate_fn=domain_src.subdomains,
    pivot_fn=domain_src.cert_sibling_roots,
    reverse_whois_fn=_DEFAULT,
    resolve_fn=domain_src.resolve_host,
    probe_fn=domain_src.http_probe,
    fetch_fn=domain_src.fetch_url,
    fetch_doc_fn=domain_src.fetch_document,
    introspect_fn=domain_src.graphql_introspect,
    wayback_fn=domain_src.wayback_paths,
    probe_url_fn=domain_src.fetch_public_url,
    dns_fn=domain_src.dns_email_posture,
    tls_fn=domain_src.tls_probe,
    ports_fn=domain_src.port_scan,
    identify_fn=None,
    cve_fn=domain_src.nvd_cves,
    provider: Provider | None = None,
    model: str | None = None,
    challenger: Provider | None = None,
    challenger_model: str | None = None,
    judge: Provider | None = None,
    judge_model: str | None = None,
    reproduce: bool = False,
    confirm: bool = False,
    reproduce_fetch_fn=domain_src.fetch_readonly,
) -> Scenario:
    # The registrant pivot is the reliable core, but its provider has no keyless mode, so
    # the real seam turns on only when a key is set. A test passes its own fake to wire it
    # without a key.
    if reverse_whois_fn is _DEFAULT:
        reverse_whois_fn = domain_src.reverse_whois if config.reverse_whois_key() else None

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
        domain.assemble(enumerate_fn=enumerate_fn, pivot_fn=pivot_fn, resolve_fn=resolve_fn,
                        probe_fn=probe_fn, fetch_fn=fetch_fn, fetch_doc_fn=fetch_doc_fn,
                        introspect_fn=introspect_fn, wayback_fn=wayback_fn,
                        probe_url_fn=probe_url_fn, dns_fn=dns_fn, tls_fn=tls_fn,
                        ports_fn=ports_fn, reverse_whois_fn=reverse_whois_fn,
                        identify_fn=identify_fn, cve_fn=cve_fn),
        github.assemble(search_fn=search_fn, repos_fn=repos_fn),
    ]
    capabilities = tuple(cap for bundle in bundles for cap in bundle.capabilities)
    map_rules = [rule for bundle in bundles for rule in bundle.map_rules]
    enrich_rules = [rule for bundle in bundles for rule in bundle.enrich_rules]
    knowledge_dirs = [bundle.knowledge_dir for bundle in bundles if bundle.knowledge_dir]

    # Confirm regrades findings against the reproduction receipts, so it needs the receipts
    # the EXPLOIT phase records, so confirm implies reproduce.
    reproduce = reproduce or confirm

    # The read-only reproduce step and its rule are always registered but dormant, the
    # EXPLOIT phase runs only when the operator raises the terminal with reproduce. It is
    # intrusive tier, so scope still demands the recorded authorization even when enabled.
    capabilities = capabilities + (ReproduceFinding(reproduce_fetch_fn),)
    rules = {Phase.MAP: map_rules, Phase.ENRICH: enrich_rules, Phase.EXPLOIT: [reproduce_rule]}

    terminal = _terminal_phase(reproduce=reproduce, confirm=confirm)

    return Scenario(
        name=NAME,
        content_root=Path(__file__).resolve().parent,
        capabilities=capabilities,
        planner=RuleSet(rules),
        triage=SurfaceTriage(knowledge_dirs, provider=provider, model=model,
                             challenger=challenger, challenger_model=challenger_model,
                             judge=judge, judge_model=judge_model),
        post_triage=FindingGrounder(),
        confirm=ConfirmTriage(provider=provider, model=model) if confirm else None,
        payloads=_payloads(),
        terminal=terminal,
    )


def seed(name: str, *, domains=(), hosts=()) -> World:
    """Build the seed world for a run, an `Org` node carrying the hint roots and the known
    inventory hosts. This is the entry a run path uses to turn operator input, whether typed
    on the command line or loaded from a seed file, into the world the engine drives."""
    world = World()
    world.add(Node(id=f"org:{name}", type="org",
                   payload=Org(name=name, domains=tuple(domains), hosts=tuple(hosts))))
    return world

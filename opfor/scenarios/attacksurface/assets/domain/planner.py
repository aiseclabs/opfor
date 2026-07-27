"""Domain-class planner rules, the pipeline that discovers and enriches the domain surface.

Discovery grows the root and subdomain set in MAP. Enrichment resolves each name, probes
the resolvable ones, harvests candidate paths, enumerates interfaces once harvesting has
run across all hosts, then expands any exposed API specification or open introspection.
The rules gate on facts rather than task dependencies, so a name that does not resolve is
never probed, and each rule that touches the target carries the host for scope.

This module composes the capability action-config the planner hands the endpoint probe, so the
capability reads no knowledge file. The backup name templates come from the finding units they
serve, and the probe path set is composed by the class from the owners of each path rather than a
global guessed list. The config is loaded once at assemble time into a `DomainPlanConfig`, not at
import, so the content root stays swappable and importing the module triggers no file IO.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from opfor.core import Task, World, each
from opfor.scenarios.attacksurface.assets.base import class_enabled

# The asset class this planner belongs to, the single source of the class name the enable gate and
# the bundle share, so the class does not self-reference by a repeated string literal.
CLASS = "domain"

# Static-asset denoise, the suffixes and prefixes the endpoint probe treats as assets rather than
# interfaces, so a hashed bundle does not bury the real routes. This is mechanical probe config, not
# attack knowledge, so it lives in code here, not the knowledge tree.
_STATIC_SUFFIXES = (".js", ".mjs", ".css", ".map", ".ico", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                    ".webp", ".avif", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".webm")
_STATIC_PREFIXES = ("/_next/static/", "/static/", "/assets/", "/_nuxt/")


@dataclass(frozen=True, kw_only=True)
class DomainPlanConfig:
    """The domain class's capability action-config, the paths to probe, the static-asset templates,
    and the backup name templates the planner hands each capability so the capability reads no
    knowledge file, invariant 1. This is action config, not triage knowledge. Loaded once at
    assemble time by `load_plan_config`, so import triggers no IO. `probe_paths` starts empty and
    the class composes it from the owners of each path, the products' own version endpoints and the
    spec and introspection locations, so there is no global guessed path list."""

    probe_paths: tuple[str, ...] = ()
    static_suffixes: tuple[str, ...] = ()
    static_prefixes: tuple[str, ...] = ()


def load_plan_config(paths) -> DomainPlanConfig:
    """Load the domain plan config, once, at build time, so the file IO the planner needs happens
    when a scenario is assembled, never at import. `paths` is the class's `KnowledgePaths`."""
    return DomainPlanConfig(
        static_suffixes=_STATIC_SUFFIXES,
        static_prefixes=_STATIC_PREFIXES,
    )


def _live_domains(world: World) -> list:
    """Every domain that answered HTTP, the hosts worth probing."""
    live = []
    for node in world.nodes("domain"):
        http = world.latest("http", node.id)
        if http is not None and http.payload.alive:
            live.append(node)
    return live


def _http_rule(world: World) -> list[Task]:
    """Probe every resolvable domain that has no HTTP fact yet.

    This gates HTTP on a resolved result rather than a task dependency, so a name that
    does not resolve is never probed, and the probe carries the domain name for scope,
    since touching the target's server is a scoped act, not a public read.
    """
    tasks: list[Task] = []
    for node in world.nodes("domain"):
        resolved = world.latest("resolved", node.id)
        if resolved is None or not resolved.payload.resolvable:
            continue
        if world.has_fact(node.id, "http"):
            continue
        tasks.append(Task(capability="domain_http", node=node.id, scope_target=node.payload.name))
    return tasks


def _harvest_rule(world: World) -> list[Task]:
    """Harvest candidate paths on every live host that has not been harvested yet.

    Harvesting comes before probing so a path a host's script names on a sibling host is
    recorded against that sibling before its interfaces are enumerated.
    """
    tasks: list[Task] = []
    for node in _live_domains(world):
        if world.has_fact(node.id, "harvested"):
            continue
        tasks.append(Task(capability="domain_harvest", node=node.id, scope_target=node.payload.name))
    return tasks


def _permute_paths_rule(world: World) -> list[Task]:
    """Derive principled path candidates on every live host once it is harvested, before the
    interface probe runs, so the probe confirms them against the host's catch-all baseline.
    Gated on the host's harvested fact so it permutes observed paths, and on its own fact so it
    runs once. It reads only gathered paths and makes no request, so it needs no scope host."""
    tasks: list[Task] = []
    for node in _live_domains(world):
        if not world.has_fact(node.id, "harvested"):
            continue
        if world.has_fact(node.id, "path_permuted"):
            continue
        tasks.append(Task(capability="domain_permute_paths", node=node.id))
    return tasks


def _endpoints_rule(world: World, config: DomainPlanConfig) -> list[Task]:
    """Enumerate interfaces on every live domain, once every live host is harvested and its
    observed paths permuted.

    The barrier holds probing until harvesting and permutation are done across all hosts, so a
    cross-host candidate and a derived path have both landed on their target before it is
    probed. Each task carries the domain name for scope and the knowledge path list.
    """
    live = _live_domains(world)
    if any(not world.has_fact(node.id, "harvested") for node in live):
        return []
    if any(not world.has_fact(node.id, "path_permuted") for node in live):
        return []
    tasks: list[Task] = []
    for node in live:
        if world.has_fact(node.id, "endpoints"):
            continue
        tasks.append(Task(capability="domain_endpoints", node=node.id,
                          params={"paths": list(config.probe_paths),
                                  "static_suffixes": list(config.static_suffixes),
                                  "static_prefixes": list(config.static_prefixes)},
                          scope_target=node.payload.name))
    return tasks


def _is_spec_endpoint(endpoint) -> bool:
    """Whether an endpoint looks like a JSON API specification worth parsing."""
    path = endpoint.path.lower()
    return (("openapi" in path or "swagger" in path or "api-docs" in path)
            and "json" in (endpoint.content_type or "").lower())


def _spec_rule(world: World) -> list[Task]:
    """Parse every reachable API specification endpoint that has not been parsed yet."""
    tasks: list[Task] = []
    for node in world.nodes("endpoint"):
        endpoint = node.payload
        if world.has_fact(node.id, "api_spec") or endpoint.auth_required:
            continue
        if not _is_spec_endpoint(endpoint):
            continue
        host = urlparse(endpoint.url).hostname or ""
        tasks.append(Task(capability="endpoint_expand_spec", node=node.id, scope_target=host))
    return tasks


def _spec_probe_rule(world: World) -> list[Task]:
    """Verify the operations each exposed specification declares, once per spec.

    Gated on the api_spec fact so it runs after the spec is parsed, and on its own
    spec_audit fact so it runs once. It probes the target's declared GET operations, a
    scoped recon act, so it carries the host for scope.
    """
    tasks: list[Task] = []
    for node in world.nodes("endpoint"):
        if not world.has_fact(node.id, "api_spec"):
            continue
        if world.has_fact(node.id, "spec_audit"):
            continue
        host = urlparse(node.payload.url).hostname or ""
        tasks.append(Task(capability="endpoint_probe_spec", node=node.id, scope_target=host))
    return tasks


def _graphql_rule(world: World) -> list[Task]:
    """Introspect every reachable GraphQL endpoint that has not been introspected yet."""
    tasks: list[Task] = []
    for node in world.nodes("endpoint"):
        endpoint = node.payload
        if world.has_fact(node.id, "graphql") or endpoint.auth_required:
            continue
        if not endpoint.path.lower().rstrip("/").endswith("/graphql"):
            continue
        host = urlparse(endpoint.url).hostname or ""
        tasks.append(Task(capability="endpoint_graphql", node=node.id, scope_target=host))
    return tasks


def _profile_rule(world: World) -> list[Task]:
    """Profile every live host once its surface is enumerated, deriving its product, front-end
    frameworks, and edge into one host_profile fact.

    Gating on the endpoints fact holds it until the version endpoints have been probed, so the
    identification has that evidence to read. It runs once per host, gated on its own fact, and
    reads facts and public sources, never the target, so it needs no scope host.
    """
    tasks: list[Task] = []
    for node in _live_domains(world):
        if not world.has_fact(node.id, "endpoints"):
            continue
        if world.has_fact(node.id, "host_profile"):
            continue
        tasks.append(Task(capability="domain_profile", node=node.id))
    return tasks


def _cve_rule(world: World) -> list[Task]:
    """Look up known vulnerabilities for every live host once it has been profiled.

    Gating on the host_profile fact holds the lookup until the product and version have been
    identified, so it reads that identity rather than deriving its own. It runs once per host,
    gated on its own fact, and touches only public sources, so it needs no scope host.
    """
    tasks: list[Task] = []
    for node in _live_domains(world):
        if not world.has_fact(node.id, "host_profile"):
            continue
        if world.has_fact(node.id, "cve_scan"):
            continue
        tasks.append(Task(capability="cve_scan", node=node.id))
    return tasks


def _permute_rule(world: World) -> list[Task]:
    """Permute observed labels into candidate subdomains, once per root, after passive
    enumeration has run so the observed set is populated. Gating on the root's `enumerated`
    fact holds the permutation until passive discovery named the labels it permutes, so it
    extends observed evidence rather than firing on an empty set."""
    tasks: list[Task] = []
    for node in world.nodes("domain"):
        payload = node.payload
        if payload.name != payload.root:
            continue
        if not world.has_fact(node.id, "enumerated"):
            continue
        if world.has_fact(node.id, "permuted"):
            continue
        tasks.append(Task(capability="domain_permute", node=node.id))
    return tasks


def map_rules():
    """The domain MAP rules. The operator's seed roots are materialized, then each root is
    expanded to its subdomains. Root discovery beyond the seed is deliberately not done, so the
    run maps exactly the roots the operator supplied, no more."""
    return [
        each("org", run="discover_domains", unless_fact="domains_discovered",
             where=lambda p: class_enabled(p, CLASS)),
        each("domain", run="domain_subdomains", unless_fact="enumerated",
             where=lambda p: p.name == p.root),
        _permute_rule,
    ]


def enrich_rules(config: DomainPlanConfig, *, with_profile: bool = False, with_cve: bool = False):
    """The domain ENRICH pipeline, resolve then probe then harvest then enumerate, then the host
    profile, then the CVE lookup that reads it, each when its seams are wired and once a host's
    surface is enumerated. The config is the capability action-config the config-driven rules
    hand their capabilities."""
    rules = [
        each("domain", run="domain_resolve", unless_fact="resolved"),
        _http_rule,
        _harvest_rule,
        _permute_paths_rule,
        lambda world: _endpoints_rule(world, config),
        _spec_rule,
        _spec_probe_rule,
        _graphql_rule,
    ]
    if with_profile:
        rules.append(_profile_rule)
    if with_cve:
        rules.append(_cve_rule)
    return rules

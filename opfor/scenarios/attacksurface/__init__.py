"""The attack-surface scenario: from an org name to a ranked map of its assets.

The seed is an `Org`, an organization the operator names, such as a company. The run
discovers assets under it across classes, GitHub orgs from the name and domains from
the operator's hint roots, expands each, GitHub repos and certificate-transparency
subdomains, resolves and probes the domains, and triages the whole into a ranked
inventory. The operator restricts to a class with `Org.classes`, empty runs them all.

It reads public sources and probes only the domains scope authorizes, and it stops at
TRIAGE, a declared finish line, so a full run is a closed run. Every source is an
injected seam, so a test drives the whole scenario with fixtures. `build` wires the
real seams.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

import yaml

from opfor.core import Phase, RuleSet, Scenario, Task, World, each
from opfor.scenarios.attacksurface import config
from opfor.scenarios.attacksurface.capabilities import (
    DiscoverDomains,
    DiscoverGitHub,
    DomainPivot,
    DomainRegistrant,
    Endpoints,
    ExpandSpec,
    GitHubRepos,
    GraphQLIntrospect,
    HarvestPaths,
    HTTPDomain,
    ResolveDomain,
    Subdomains,
)
from opfor.scenarios.attacksurface.sources import domains as domain_src
from opfor.scenarios.attacksurface.sources import github as github_src
from opfor.scenarios.attacksurface.triage import SurfaceTriage

# Sentinel so build can tell an unset reverse-WHOIS seam from one a caller passed, even
# a fake in a test, and default the real seam to on only when a provider key is set.
_DEFAULT = object()

_PATHS = yaml.safe_load(
    (Path(__file__).resolve().parent / "knowledge" / "paths.yaml").read_text(encoding="utf-8")
) or {}
_PROBE_PATHS = [str(p) for p in (_PATHS.get("paths") or [])]


def _enabled(org, asset_class: str) -> bool:
    """Whether an asset class runs, given the org's optional class restriction."""
    return not org.classes or asset_class in org.classes


def inventory(world: World) -> list[tuple[str, list[str]]]:
    """The run's raw inventory as headed line groups for a report, read from the world.

    This is the full picture behind the findings, every root, live host, dangling name,
    and unauthenticated interface, so a report carries the map and not only the issues.
    """
    domains = world.nodes("domain")
    roots = sorted((n.payload for n in domains if n.payload.name == n.payload.root),
                   key=lambda p: p.root)
    live: list[str] = []
    dangling: list[str] = []
    for node in sorted(domains, key=lambda n: n.payload.name):
        payload = node.payload
        http = world.latest("http", node.id)
        resolved = world.latest("resolved", node.id)
        if http is not None and http.payload.alive:
            title = f" {http.payload.title}" if http.payload.title else ""
            live.append(f"- `{payload.name}` {http.payload.status}{title}")
        elif resolved is not None and not resolved.payload.resolvable and payload.source == "passive":
            dangling.append(f"- `{payload.name}`")
    endpoints = sorted((n.payload for n in world.nodes("endpoint") if not n.payload.auth_required),
                       key=lambda p: p.url)
    orgs = sorted(world.nodes("github_org"), key=lambda n: n.payload.login)
    return [
        (f"Root domains ({len(roots)})",
         [f"- `{r.root}` ({r.source})" + (f", {r.evidence}" if r.evidence else "") for r in roots]),
        (f"Live hosts ({len(live)})", live),
        (f"Dangling names ({len(dangling)})", dangling),
        (f"Unauthenticated interfaces ({len(endpoints)})", [f"- `{e.url}`" for e in endpoints]),
        (f"GitHub orgs ({len(orgs)})", [f"- `{n.payload.login}` {n.payload.url}" for n in orgs]),
    ]


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
        tasks.append(Task(capability="domain_http", node=node.id, scope_host=node.payload.name))
    return tasks


def _live_domains(world: World) -> list:
    """Every domain that answered HTTP, the hosts worth probing."""
    live = []
    for node in world.nodes("domain"):
        http = world.latest("http", node.id)
        if http is not None and http.payload.alive:
            live.append(node)
    return live


def _harvest_rule(world: World) -> list[Task]:
    """Harvest candidate paths on every live host that has not been harvested yet.

    Harvesting comes before probing so a path a host's script names on a sibling host is
    recorded against that sibling before its interfaces are enumerated.
    """
    tasks: list[Task] = []
    for node in _live_domains(world):
        if world.has_fact(node.id, "harvested"):
            continue
        tasks.append(Task(capability="domain_harvest", node=node.id, scope_host=node.payload.name))
    return tasks


def _endpoints_rule(world: World) -> list[Task]:
    """Enumerate interfaces on every live domain, once every live host is harvested.

    The barrier holds probing until harvesting is done across all hosts, so a cross-host
    candidate has landed on its target before that target is probed. Each task carries the
    domain name for scope and the knowledge path list for the capability.
    """
    live = _live_domains(world)
    if any(not world.has_fact(node.id, "harvested") for node in live):
        return []
    tasks: list[Task] = []
    for node in live:
        if world.has_fact(node.id, "endpoints"):
            continue
        tasks.append(Task(capability="domain_endpoints", node=node.id,
                          params={"paths": _PROBE_PATHS}, scope_host=node.payload.name))
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
        tasks.append(Task(capability="endpoint_expand_spec", node=node.id, scope_host=host))
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
        tasks.append(Task(capability="endpoint_graphql", node=node.id, scope_host=host))
    return tasks


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
) -> Scenario:
    # The registrant pivot is the reliable core, but its provider has no keyless mode, so
    # the real seam turns on only when a key is set. A test passes its own fake to wire it
    # without a key.
    if reverse_whois_fn is _DEFAULT:
        reverse_whois_fn = domain_src.reverse_whois if config.reverse_whois_key() else None

    root = Path(__file__).resolve().parent
    capabilities = [
        DiscoverDomains(),
        DiscoverGitHub(search_fn),
        DomainPivot(pivot_fn),
        Subdomains(enumerate_fn),
        ResolveDomain(resolve_fn),
        HTTPDomain(probe_fn),
        HarvestPaths(fetch_fn, fetch_doc_fn, wayback_fn),
        Endpoints(fetch_fn),
        ExpandSpec(fetch_doc_fn),
        GraphQLIntrospect(introspect_fn),
        GitHubRepos(repos_fn),
    ]
    map_rules = [
        each("org", run="discover_domains", unless_fact="domains_discovered",
             where=lambda p: _enabled(p, "domain")),
        each("org", run="discover_github", unless_fact="github_discovered",
             where=lambda p: _enabled(p, "github")),
        each("domain", run="domain_pivot", unless_fact="pivoted",
             where=lambda p: p.name == p.root),
        each("domain", run="domain_subdomains", unless_fact="enumerated",
             where=lambda p: p.name == p.root),
    ]
    if reverse_whois_fn is not None:
        capabilities.append(DomainRegistrant(reverse_whois_fn))
        map_rules.append(each("org", run="domain_registrant", unless_fact="registrant",
                              where=lambda p: _enabled(p, "domain")))

    return Scenario(
        name="attacksurface",
        content_root=root,
        capabilities=tuple(capabilities),
        planner=RuleSet({
            Phase.MAP: map_rules,
            Phase.ENRICH: [
                each("domain", run="domain_resolve", unless_fact="resolved"),
                _http_rule,
                _harvest_rule,
                _endpoints_rule,
                _spec_rule,
                _graphql_rule,
                each("github_org", run="github_repos", unless_fact="repos"),
            ],
        }),
        triage=SurfaceTriage(root),
        terminal=Phase.TRIAGE,
    )


ATTACKSURFACE = build()

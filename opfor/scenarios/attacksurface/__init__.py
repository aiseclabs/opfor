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

import yaml

from opfor.core import Phase, RuleSet, Scenario, Task, World, each
from opfor.scenarios.attacksurface import config
from opfor.scenarios.attacksurface.capabilities import (
    BruteSubdomains,
    DiscoverDomains,
    DiscoverGithub,
    DomainPivot,
    DomainRegistrant,
    Endpoints,
    GithubRepos,
    HttpDomain,
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

_WORDS = [
    line.strip()
    for line in (Path(__file__).resolve().parent / "knowledge" / "subdomains.txt")
    .read_text(encoding="utf-8").splitlines()
    if line.strip() and not line.startswith("#")
]


def _enabled(org, asset_class: str) -> bool:
    """Whether an asset class runs, given the org's optional class restriction."""
    return not org.classes or asset_class in org.classes


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


def _brute_rule(world: World) -> list[Task]:
    """Brute force subdomains on every root that has not been brute forced yet.

    Runs on a root regardless of how it was found, so a pivoted or registrant root is
    enumerated too, and hands the capability the knowledge wordlist. Resolving over a
    public resolver is osint, so the task names no host for scope.
    """
    tasks: list[Task] = []
    for node in world.nodes("domain"):
        payload = node.payload
        if payload.name != payload.root:
            continue
        if world.has_fact(node.id, "bruteforced"):
            continue
        tasks.append(Task(capability="domain_bruteforce", node=node.id, params={"words": _WORDS}))
    return tasks


def _endpoints_rule(world: World) -> list[Task]:
    """Enumerate interfaces on every live domain that has none yet.

    Gated on an alive HTTP result, so only a reachable host is probed, and the task
    carries the domain name for scope and the knowledge path list for the capability.
    """
    tasks: list[Task] = []
    for node in world.nodes("domain"):
        http = world.latest("http", node.id)
        if http is None or not http.payload.alive:
            continue
        if world.has_fact(node.id, "endpoints"):
            continue
        tasks.append(Task(capability="domain_endpoints", node=node.id,
                          params={"paths": _PROBE_PATHS}, scope_host=node.payload.name))
    return tasks


def build(
    *,
    search_fn=github_src.search_orgs,
    repos_fn=github_src.org_repos,
    enumerate_fn=domain_src.subdomains,
    brute_fn=domain_src.brute_subdomains,
    pivot_fn=domain_src.cert_sibling_roots,
    reverse_whois_fn=_DEFAULT,
    resolve_fn=domain_src.resolve_host,
    probe_fn=domain_src.http_probe,
    fetch_fn=domain_src.fetch_url,
) -> Scenario:
    # The registrant pivot is the reliable core, but its provider has no keyless mode, so
    # the real seam turns on only when a key is set. A test passes its own fake to wire it
    # without a key.
    if reverse_whois_fn is _DEFAULT:
        reverse_whois_fn = domain_src.reverse_whois if config.reverse_whois_key() else None

    root = Path(__file__).resolve().parent
    capabilities = [
        DiscoverDomains(),
        DiscoverGithub(search_fn),
        DomainPivot(pivot_fn),
        Subdomains(enumerate_fn),
        BruteSubdomains(brute_fn),
        ResolveDomain(resolve_fn),
        HttpDomain(probe_fn),
        Endpoints(fetch_fn),
        GithubRepos(repos_fn),
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
        _brute_rule,
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
                _endpoints_rule,
                each("github_org", run="github_repos", unless_fact="repos"),
            ],
        }),
        triage=SurfaceTriage(root),
        terminal=Phase.TRIAGE,
    )


ATTACKSURFACE = build()

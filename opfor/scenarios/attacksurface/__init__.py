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
from opfor.scenarios.attacksurface.capabilities import (
    DiscoverDomains,
    DiscoverGithub,
    Endpoints,
    GithubRepos,
    HttpDomain,
    ResolveDomain,
    Subdomains,
)
from opfor.scenarios.attacksurface.sources import domains as domain_src
from opfor.scenarios.attacksurface.sources import github as github_src
from opfor.scenarios.attacksurface.triage import SurfaceTriage

_PATHS = yaml.safe_load(
    (Path(__file__).resolve().parent / "knowledge" / "paths.yaml").read_text(encoding="utf-8")
) or {}
_PROBE_PATHS = [str(p) for p in (_PATHS.get("paths") or [])]


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
    resolve_fn=domain_src.resolve_host,
    probe_fn=domain_src.http_probe,
    fetch_fn=domain_src.fetch_url,
) -> Scenario:
    root = Path(__file__).resolve().parent
    return Scenario(
        name="attacksurface",
        content_root=root,
        capabilities=(
            DiscoverDomains(),
            DiscoverGithub(search_fn),
            Subdomains(enumerate_fn),
            ResolveDomain(resolve_fn),
            HttpDomain(probe_fn),
            Endpoints(fetch_fn),
            GithubRepos(repos_fn),
        ),
        planner=RuleSet({
            Phase.MAP: [
                each("org", run="discover_domains", unless_fact="domains_discovered",
                     where=lambda p: _enabled(p, "domain")),
                each("org", run="discover_github", unless_fact="github_discovered",
                     where=lambda p: _enabled(p, "github")),
                each("domain", run="domain_subdomains", unless_fact="enumerated",
                     where=lambda p: p.source == "hint"),
            ],
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

"""Attack-surface capabilities, grouped by asset class. Each fetches, none judges.

Two discovery capabilities expand an org into assets, a domain hint list into domain
nodes and an org name into GitHub org nodes, so a bare name grows a surface. The rest
enrich one asset, subdomains and DNS and HTTP for a domain, repositories for a GitHub
org. Certificate transparency, DNS, and the GitHub API are public reads, so they are
osint. Only the HTTP probe touches the target, so it is a scoped recon act and carries
the domain name for scope. A source error becomes a loud `Failed`, never an empty `Done`.
"""

from __future__ import annotations

from opfor.core import Capability, Done, Fact, Failed, Node, Outcome, Phase, Task, World
from opfor.scenarios.attacksurface import config
from opfor.scenarios.attacksurface.types import (
    DomainData,
    GithubOrg,
    GithubRepo,
    Http,
    Resolved,
)


class DiscoverDomains(Capability):
    """MAP: turn the org's hint domains into domain nodes, the roots of the domain class.

    Discovering domains from a bare name needs a paid reverse-lookup source, so this
    seeds from the operator's hints. A keyed source would slot in here later, the hints
    keep a run working with none.
    """

    name = "discover_domains"
    phase = Phase.MAP

    def run(self, task: Task, world: World) -> Outcome:
        org = world.node(task.node).payload
        found = tuple(
            Node(id=f"domain:{d}", type="domain",
                 payload=DomainData(name=d, root=d, source="hint"))
            for d in org.domains
        )
        return Done(facts=(Fact(kind="domains_discovered", about=task.node, yields=found),))


class DiscoverGithub(Capability):
    """MAP: search GitHub for orgs matching the name, as new github_org nodes."""

    name = "discover_github"
    phase = Phase.MAP

    def __init__(self, search_fn) -> None:
        self._search = search_fn

    def run(self, task: Task, world: World) -> Outcome:
        org = world.node(task.node).payload
        try:
            orgs = self._search(org.name, config.github_token())
        except Exception as exc:
            return Failed(reason=f"github search {type(exc).__name__}: {exc}")
        found = tuple(
            Node(id=f"github_org:{o['login']}", type="github_org",
                 payload=GithubOrg(login=o["login"], url=o.get("url", ""), org_id=o.get("org_id")))
            for o in orgs
        )
        return Done(facts=(Fact(kind="github_discovered", about=task.node, yields=found),))


class Subdomains(Capability):
    """MAP: certificate transparency subdomains of a domain root, as new domain nodes."""

    name = "domain_subdomains"
    phase = Phase.MAP

    def __init__(self, enumerate_fn) -> None:
        self._enumerate = enumerate_fn

    def run(self, task: Task, world: World) -> Outcome:
        root = world.node(task.node).payload.name
        try:
            names = self._enumerate(root)
        except Exception as exc:
            return Failed(reason=f"crt.sh {type(exc).__name__}: {exc}")
        found = tuple(
            Node(id=f"domain:{n}", type="domain",
                 payload=DomainData(name=n, root=root, source="crt"))
            for n in sorted(names) if n != root
        )
        return Done(facts=(Fact(kind="enumerated", about=task.node, yields=found),))


class ResolveDomain(Capability):
    """ENRICH: resolve a domain to its addresses, or mark it dangling."""

    name = "domain_resolve"
    phase = Phase.ENRICH

    def __init__(self, resolve_fn) -> None:
        self._resolve = resolve_fn

    def run(self, task: Task, world: World) -> Outcome:
        name = world.node(task.node).payload.name
        try:
            result = self._resolve(name)
        except Exception as exc:
            return Failed(reason=f"resolve {type(exc).__name__}: {exc}")
        payload = Resolved(resolvable=bool(result["resolvable"]),
                           addresses=tuple(result.get("addresses", ())))
        return Done(facts=(Fact(kind="resolved", about=task.node, payload=payload),))


class HttpDomain(Capability):
    """ENRICH: probe a resolvable domain over HTTP, capturing status and body head."""

    name = "domain_http"
    phase = Phase.ENRICH
    osint = False  # probing the target's own server is a scoped act, not a public read

    def __init__(self, probe_fn) -> None:
        self._probe = probe_fn

    def run(self, task: Task, world: World) -> Outcome:
        name = world.node(task.node).payload.name
        try:
            result = self._probe(name)
        except Exception as exc:
            return Failed(reason=f"http {type(exc).__name__}: {exc}")
        payload = Http(
            alive=bool(result["alive"]),
            status=result.get("status"),
            url=str(result.get("url", "")),
            server=str(result.get("server", "")),
            title=str(result.get("title", "")),
            body=str(result.get("body", "")),
        )
        return Done(facts=(Fact(kind="http", about=task.node, payload=payload),))


class GithubRepos(Capability):
    """ENRICH: list a GitHub org's public repositories, as new github_repo nodes."""

    name = "github_repos"
    phase = Phase.ENRICH

    def __init__(self, repos_fn) -> None:
        self._repos = repos_fn

    def run(self, task: Task, world: World) -> Outcome:
        login = world.node(task.node).payload.login
        try:
            repos = self._repos(login, config.github_token())
        except Exception as exc:
            return Failed(reason=f"github repos {type(exc).__name__}: {exc}")
        found = tuple(
            Node(id=f"github_repo:{r['full_name']}", type="github_repo",
                 payload=GithubRepo(full_name=r["full_name"], url=r.get("url", ""),
                                    language=r.get("language", ""), pushed_at=r.get("pushed_at", ""),
                                    archived=bool(r.get("archived"))))
            for r in repos
        )
        return Done(facts=(Fact(kind="repos", about=task.node, yields=found),))

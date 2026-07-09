"""Attack-surface capabilities, grouped by asset class. Each fetches, none judges.

Two discovery capabilities expand an org into assets, a domain hint list into domain
nodes and an org name into GitHub org nodes, so a bare name grows a surface. The rest
enrich one asset, subdomains and DNS and HTTP for a domain, repositories for a GitHub
org. Certificate transparency, DNS, and the GitHub API are public reads, so they are
osint. Only the HTTP probe touches the target, so it is a scoped recon act and carries
the domain name for scope. A source error becomes a loud `Failed`, never an empty `Done`.
"""

from __future__ import annotations

import re

from opfor.core import Capability, Done, Fact, Failed, Node, Outcome, Phase, Task, World
from opfor.scenarios.attacksurface import config
from opfor.scenarios.attacksurface.types import (
    DomainData,
    Endpoint,
    GithubOrg,
    GithubRepo,
    Http,
    Resolved,
)

_LINK = re.compile(r'(?:href|src)\s*=\s*["\']([^"\'#?]+)', re.IGNORECASE)


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
        resolved = world.latest("resolved", task.node)
        addresses = resolved.payload.addresses if resolved else ()
        try:
            result = self._probe(name, addresses)
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


class Endpoints(Capability):
    """ENRICH: probe a live host's interface paths, recording which need no auth.

    The path list is knowledge, handed in by the planner, so this capability reads no
    file. It probes each path plus any same-origin link found on the home page, and
    records every path that answered, tagging 401 or 403 as auth required. Probing is a
    scoped recon act, GET only, no payload, so it carries the domain name for scope.
    """

    name = "domain_endpoints"
    phase = Phase.ENRICH
    osint = False

    def __init__(self, fetch_fn) -> None:
        self._fetch = fetch_fn

    # Unlikely paths, probed first to learn how a host answers a path that does not
    # exist. A single-page app returns its 200 HTML for these too, which is the catch-all
    # an endpoint must differ from to count as real.
    _BASELINE_PATHS = ("/opfor-baseline-6f3a9c2e", "/does-not-exist-8b1d.html")

    def run(self, task: Task, world: World) -> Outcome:
        node = world.node(task.node)
        name = node.payload.name
        resolved = world.latest("resolved", task.node)
        addresses = resolved.payload.addresses if resolved else ()
        http = world.latest("http", task.node)
        paths = list(task.params.get("paths") or [])
        home_body = http.payload.body if http else ""
        candidates = list(dict.fromkeys(paths + _home_paths(home_body)))
        baseline = self._baseline(name, addresses)
        endpoints: list[Node] = []
        for path in candidates:
            try:
                result = self._fetch(name, addresses, path)
            except Exception:
                continue
            status = result.get("status")
            if status is None or status == 404:
                continue
            if not _distinct(result, baseline):
                continue
            payload = Endpoint(
                url=result.get("url", f"https://{name}{path}"),
                path=path,
                status=status,
                auth_required=status in (401, 403),
                content_type=str(result.get("content_type", "")),
                server=str(result.get("server", "")),
                title=str(result.get("title", "")),
                body=str(result.get("body", "")),
            )
            endpoints.append(Node(id=f"endpoint:{name}{path}", type="endpoint", payload=payload))
        return Done(facts=(Fact(kind="endpoints", about=task.node, yields=tuple(endpoints)),))

    def _baseline(self, name, addresses) -> dict:
        """The host's answer to a path that does not exist, its catch-all signature."""
        for path in self._BASELINE_PATHS:
            try:
                result = self._fetch(name, addresses, path)
            except Exception:
                continue
            if result.get("status") is not None:
                return result
        return {"status": None, "content_type": "", "body": ""}


def _distinct(result: dict, baseline: dict) -> bool:
    """Whether a response is a real endpoint rather than the host's catch-all.

    When the catch-all is a positive page, a single-page app that answers 200 for every
    path, an endpoint counts only if it differs in status, in content type, or clearly in
    body size. When the catch-all was a 404 or a redirect, any answer that got past the
    404 filter is already a real endpoint.
    """
    base_status = baseline.get("status")
    if base_status is None:
        return True
    if result.get("status") != base_status:
        return True
    if not (200 <= int(base_status) < 300):
        return False
    if _ct_family(result.get("content_type", "")) != _ct_family(baseline.get("content_type", "")):
        return True
    return abs(len(result.get("body", "")) - len(baseline.get("body", ""))) > 128


def _ct_family(content_type: str) -> str:
    return (content_type or "").split(";")[0].strip().lower()


def _home_paths(body: str, *, limit: int = 20) -> list[str]:
    """Same-origin absolute paths linked from a home page body, deduped and capped."""
    out: list[str] = []
    for href in _LINK.findall(body or ""):
        if href.startswith("/") and not href.startswith("//") and href not in out:
            out.append(href)
        if len(out) >= limit:
            break
    return out


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

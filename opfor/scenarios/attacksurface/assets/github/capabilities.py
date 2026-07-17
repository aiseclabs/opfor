"""GitHub-class capabilities, each fetches, none judges.

One discovery capability turns the org name into GitHub org nodes, attributing each by
the domain its profile links to, so a namesake is not passed off as the target's. One
enrichment lists an attributed org's public repositories. Both read the public GitHub
API, so they are osint. A source error becomes a loud `Failed`, never an empty `Done`.
"""

from __future__ import annotations

from urllib.parse import urlparse

from opfor.core import Capability, Done, Fact, Failed, Node, Outcome, Phase, Task, World
from opfor.scenarios.attacksurface import config
from opfor.scenarios.attacksurface.net import registrable_root
from opfor.scenarios.attacksurface.assets.github.types import GitHubOrg, GitHubRepo


def _site_domain(value: str) -> str:
    """The hostname a website URL or an email address points at, empty when there is none."""
    value = value.strip().lower()
    if not value:
        return ""
    if "@" in value:
        return value.rsplit("@", 1)[-1]
    return urlparse(value if "//" in value else "//" + value).hostname or ""


class DiscoverGitHub(Capability):
    """MAP: search GitHub for orgs matching the name, as new github_org nodes.

    Attribution is the cross-class seam, the one place the GitHub class reads a domain
    fact, a GitHub org is tied to the target by the domain its profile links to. So it
    reads the org's in-scope roots, the hint domains and the registrable root of each
    inventory host, and `registrable_root` from the shared net primitive, never the domain
    class itself.
    """

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
        # A name match alone does not prove ownership, so a candidate is attributed by the
        # domain its profile links to. Linking to an in-scope root confirms it. Linking to a
        # different registrable root is positive counter-evidence that it belongs to someone
        # else, so it is dropped. No link leaves it a name match, kept but marked unattributed.
        targets = set(org.domains) | {registrable_root(h) for h in org.hosts}
        found = []
        for o in orgs:
            site = _site_domain(o.get("blog") or o.get("email") or "")
            site_root = registrable_root(site) if site else ""
            if site_root and targets and site_root not in targets:
                continue
            attributed = bool(site_root and site_root in targets)
            evidence = (f"profile links to {site_root}" if attributed
                        else "account name matches, ownership not established")
            found.append(Node(id=f"github_org:{o['login']}", type="github_org",
                              payload=GitHubOrg(login=o["login"], url=o.get("url", ""),
                                                org_id=o.get("org_id"), name=o.get("name", ""),
                                                website=o.get("blog", ""), attributed=attributed,
                                                evidence=evidence)))
        return Done(facts=(Fact(kind="github_discovered", about=task.node, yields=tuple(found)),))


class GitHubRepos(Capability):
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
                 payload=GitHubRepo(full_name=r["full_name"], url=r.get("url", ""),
                                    language=r.get("language", ""), pushed_at=r.get("pushed_at", ""),
                                    archived=bool(r.get("archived"))))
            for r in repos
        )
        return Done(facts=(Fact(kind="repos", about=task.node, yields=found),))

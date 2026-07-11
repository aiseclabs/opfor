"""Attack-surface capabilities, grouped by asset class. Each fetches, none judges.

Two discovery capabilities expand an org into assets, a domain hint list into domain
nodes and an org name into GitHub org nodes, so a bare name grows a surface. The rest
enrich one asset, subdomains and DNS and HTTP for a domain, repositories for a GitHub
org. Certificate transparency, DNS, and the GitHub API are public reads, so they are
osint. Only the HTTP probe touches the target, so it is a scoped recon act and carries
the domain name for scope. A source error becomes a loud `Failed`, never an empty `Done`.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from opfor.core import Capability, Done, Fact, Failed, Node, Outcome, Phase, Task, World
from opfor.scenarios.attacksurface import config
from opfor.scenarios.attacksurface.sources.domains import (
    operations_from_introspection,
    paths_from_openapi,
    paths_in_javascript,
    registrable_root,
    robots_entries,
    same_host_path,
    script_sources,
    sitemap_paths,
    urls_in_javascript,
)
from opfor.scenarios.attacksurface.types import (
    APISpec,
    Candidates,
    DomainData,
    Endpoint,
    GitHubOrg,
    GitHubRepo,
    GraphQLSchema,
    HTTP,
    Resolved,
)

def _site_domain(value: str) -> str:
    """The hostname a website URL or an email address points at, empty when there is none."""
    value = value.strip().lower()
    if not value:
        return ""
    if "@" in value:
        return value.rsplit("@", 1)[-1]
    return urlparse(value if "//" in value else "//" + value).hostname or ""


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
        roots = tuple(
            Node(id=f"domain:{d}", type="domain",
                 payload=DomainData(name=d, root=d, source="hint",
                                    confidence="confirmed", evidence="operator hint"))
            for d in org.domains
        )
        # Inventory hosts enter as leaves under their registrable root, not as roots, so the
        # pivot and subdomain rules, gated on name == root, skip them, and only resolution
        # and probing enrich them. This is how a DNS export closes the wildcard blind spot.
        hosts = tuple(
            Node(id=f"domain:{h}", type="domain",
                 payload=DomainData(name=h, root=registrable_root(h), source="inventory",
                                    confidence="confirmed", evidence="operator inventory"))
            for h in org.hosts
        )
        return Done(facts=(Fact(kind="domains_discovered", about=task.node, yields=roots + hosts),))


class DiscoverGitHub(Capability):
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


class DomainPivot(Capability):
    """MAP: sibling root domains that share a certificate with a known root.

    A certificate names every host its holder proved control of, so a root bundled on
    the same certificate as a confirmed root is owned by the same party. This grows the
    set of roots from evidence, not from guessing a brand across every suffix, and since
    MAP loops to quiescence a newly found root pivots again, a snowball. It reads a
    public log, so it is osint.
    """

    name = "domain_pivot"
    phase = Phase.MAP

    def __init__(self, pivot_fn) -> None:
        self._pivot = pivot_fn

    def run(self, task: Task, world: World) -> Outcome:
        name = world.node(task.node).payload.name
        try:
            siblings = self._pivot(name)
        except Exception as exc:
            return Failed(reason=f"cert pivot {type(exc).__name__}: {exc}")
        found = tuple(
            Node(id=f"domain:{root}", type="domain",
                 payload=DomainData(name=root, root=root, source="cert-san",
                                    confidence="confirmed", evidence=evidence))
            for root, evidence in sorted(siblings.items())
        )
        return Done(facts=(Fact(kind="pivoted", about=task.node, yields=found),))


class DomainRegistrant(Capability):
    """MAP: sibling root domains that share a registrant with the org, via reverse-WHOIS.

    Ownership by registration is the definitional signal of who a domain belongs to, so a
    root whose registration record names the same registrant is owned by the same party.
    The search terms are a registrant identity tied to the org, an organization name or a
    known registrant email, handed in by the planner from `Org.whois_terms`, and the org
    name is the fallback term. It reads a public registration index through a keyed
    provider, so it is osint. Wired only when a key is set.
    """

    name = "domain_registrant"
    phase = Phase.MAP

    def __init__(self, reverse_fn) -> None:
        self._reverse = reverse_fn

    def run(self, task: Task, world: World) -> Outcome:
        org = world.node(task.node).payload
        terms = org.whois_terms or (org.name,)
        key = config.reverse_whois_key()
        roots: dict[str, str] = {}
        for term in terms:
            try:
                roots.update(self._reverse(term, key))
            except Exception as exc:
                return Failed(reason=f"reverse-whois {type(exc).__name__}: {exc}")
        found = tuple(
            Node(id=f"domain:{root}", type="domain",
                 payload=DomainData(name=root, root=root, source="reverse-whois",
                                    confidence="confirmed", evidence=evidence))
            for root, evidence in sorted(roots.items())
        )
        return Done(facts=(Fact(kind="registrant", about=task.node, yields=found),))


class Subdomains(Capability):
    """MAP: passively discovered subdomains of a root, as new domain nodes.

    The source is a union of public passive sources, certificate transparency and a
    passive-DNS provider, so a name here was seen in the wild without touching the target.
    """

    name = "domain_subdomains"
    phase = Phase.MAP

    def __init__(self, enumerate_fn) -> None:
        self._enumerate = enumerate_fn

    def run(self, task: Task, world: World) -> Outcome:
        root = world.node(task.node).payload.name
        try:
            names = self._enumerate(root)
        except Exception as exc:
            return Failed(reason=f"passive enumeration {type(exc).__name__}: {exc}")
        # A wildcard such as *.dev.example.com names its base but hides every host under it
        # from certificate transparency, so the base is recorded once and flagged, and the
        # flag is what triage reports as a blind spot rather than a silent gap.
        wildcard: dict[str, bool] = {}
        for name in names:
            base = name[2:] if name.startswith("*.") else name
            if base and base != root:
                wildcard[base] = wildcard.get(base, False) or name.startswith("*.")
        found = tuple(
            Node(id=f"domain:{base}", type="domain",
                 payload=DomainData(name=base, root=root, source="passive", wildcard=is_wild))
            for base, is_wild in sorted(wildcard.items())
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
                           addresses=tuple(result.get("addresses", ())),
                           cnames=tuple(result.get("cnames", ())))
        return Done(facts=(Fact(kind="resolved", about=task.node, payload=payload),))


class HTTPDomain(Capability):
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
        payload = HTTP(
            alive=bool(result["alive"]),
            status=result.get("status"),
            url=str(result.get("url", "")),
            server=str(result.get("server", "")),
            title=str(result.get("title", "")),
            body=str(result.get("body", "")),
        )
        return Done(facts=(Fact(kind="http", about=task.node, payload=payload),))


class HarvestPaths(Capability):
    """ENRICH: gather candidate interface paths for a live host from what it reveals.

    It reads the home page links and script bundles, the robots and sitemap, and the
    passive url history, and it reads the API paths a script hardcodes. A path a script
    names by full url on another in-scope host is attributed to that host, so a single-page
    app that calls its API on a sibling host maps that host's surface too. It records only
    candidates, the probing and the judgment come later, and it touches the target, so it
    carries the host for scope. Individual sources are best effort, so it always records a
    harvested fact, an empty one is a real result rather than a stall.
    """

    name = "domain_harvest"
    phase = Phase.ENRICH
    osint = False

    _MAX_SCRIPTS = 12

    def __init__(self, fetch_fn, fetch_doc_fn, wayback_fn) -> None:
        self._fetch = fetch_fn
        self._fetch_doc = fetch_doc_fn
        self._wayback = wayback_fn

    def run(self, task: Task, world: World) -> Outcome:
        name = world.node(task.node).payload.name
        resolved = world.latest("resolved", task.node)
        addresses = resolved.payload.addresses if resolved else ()
        by_host: dict[str, set[str]] = {}

        def add(host: str, path: str) -> None:
            if host and path and path.startswith("/"):
                by_host.setdefault(host, set()).add(path.split("#")[0].split("?")[0])

        home = _safe(lambda: self._fetch_doc(name, "/").get("text", "")) or ""
        for path in _home_paths(home):
            add(name, path)
        for path in _safe(lambda: self._robots(name, addresses)) or []:
            add(name, path)
        for path in _safe(lambda: sitemap_paths(self._fetch_doc(name, "/sitemap.xml").get("text", ""), name)) or []:
            add(name, path)
        for script in script_sources(home, name)[:self._MAX_SCRIPTS]:
            body = _safe(lambda s=script: self._fetch_doc(name, s).get("text", "")) or ""
            for path in paths_in_javascript(body):
                add(name, path)
            for url in urls_in_javascript(body):
                parsed = urlparse(url)
                add(parsed.hostname or "", parsed.path or "/")
        for path in sorted(_safe(lambda: self._wayback(name)) or set()):
            add(name, path)

        facts = [Fact(kind="harvested", about=task.node)]
        for host, paths in by_host.items():
            node_id = f"domain:{host}"
            if world.node(node_id) is None:
                continue
            facts.append(Fact(kind="candidates", about=node_id,
                              payload=Candidates(source="harvest", paths=tuple(sorted(paths)))))
        return Done(facts=tuple(facts))

    def _robots(self, name, addresses) -> list[str]:
        robots = self._fetch(name, addresses, "/robots.txt")
        if robots.get("status") != 200:
            return []
        paths, sitemaps = robots_entries(robots.get("body", ""))
        for sitemap in sitemaps[:3]:
            path = same_host_path(sitemap, name)
            if path:
                paths += _safe(lambda p=path: sitemap_paths(self._fetch_doc(name, p).get("text", ""), name)) or []
        return paths


class Endpoints(Capability):
    """ENRICH: probe a host's candidate interface paths, recording which need no auth.

    The candidates are the knowledge list the planner hands in plus everything harvested
    for this host, its own and any a sibling host's script named for it. Each answered path
    is recorded, 401 or 403 tagged as auth required. Probing is a scoped recon act, GET
    only, no payload, so it carries the domain name for scope.
    """

    name = "domain_endpoints"
    phase = Phase.ENRICH
    osint = False

    _MAX_CANDIDATES = 400

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
        seed = list(task.params.get("paths") or [])
        for fact in world.facts("candidates", task.node):
            seed += list(fact.payload.paths)
        suffixes = tuple(task.params.get("static_suffixes") or ())
        prefixes = tuple(task.params.get("static_prefixes") or ())
        candidates = self._clean(seed, suffixes, prefixes)
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
                location=str(result.get("location", "")),
            )
            endpoints.append(Node(id=f"endpoint:{name}{path}", type="endpoint", payload=payload))
        return Done(facts=(Fact(kind="endpoints", about=task.node, yields=tuple(endpoints)),))

    def _clean(self, paths, suffixes, prefixes) -> list[str]:
        out: list[str] = []
        for path in paths:
            if not path or not path.startswith("/") or _is_static_asset(path, suffixes, prefixes):
                continue
            if path not in out:
                out.append(path)
            if len(out) >= self._MAX_CANDIDATES:
                break
        return out

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


def _safe(thunk):
    """Run a candidate source, returning None on any error so the union tolerates it."""
    try:
        return thunk()
    except Exception:
        return None


def _is_static_asset(path: str, suffixes, prefixes) -> bool:
    """Whether a path is a static asset, given the suffix and prefix lists the planner
    handed in from knowledge, so the capability itself reads no knowledge file."""
    lowered = path.lower().split("?")[0]
    return lowered.endswith(tuple(suffixes)) or lowered.startswith(tuple(prefixes))


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


class ExpandSpec(Capability):
    """ENRICH: parse an exposed API specification into the operations it declares.

    A single exposed OpenAPI or Swagger document maps a whole unauthenticated API, so this
    fetches the full document, the probe kept only a head, and records the declared paths.
    Fetching the target's own file is a scoped recon act, so it carries the host for scope.
    """

    name = "endpoint_expand_spec"
    phase = Phase.ENRICH
    osint = False

    def __init__(self, fetch_doc_fn) -> None:
        self._fetch = fetch_doc_fn

    def run(self, task: Task, world: World) -> Outcome:
        endpoint = world.node(task.node).payload
        host = urlparse(endpoint.url).hostname or ""
        try:
            document = self._fetch(host, endpoint.path)
        except Exception as exc:
            return Failed(reason=f"spec fetch {type(exc).__name__}: {exc}")
        try:
            parsed = json.loads(document.get("text") or "")
        except Exception:
            parsed = {}
        paths = paths_from_openapi(parsed)
        payload = APISpec(base=endpoint.url, paths=tuple(paths), count=len(paths))
        return Done(facts=(Fact(kind="api_spec", about=task.node, payload=payload),))


class GraphQLIntrospect(Capability):
    """ENRICH: introspect an open GraphQL endpoint into the operations it exposes.

    Introspection enabled in production maps the entire API, so this sends one read-only
    introspection query and records whether it answered and the operations it named.
    Sending the query touches the target, so it carries the host for scope.
    """

    name = "endpoint_graphql"
    phase = Phase.ENRICH
    osint = False

    def __init__(self, introspect_fn) -> None:
        self._introspect = introspect_fn

    def run(self, task: Task, world: World) -> Outcome:
        endpoint = world.node(task.node).payload
        host = urlparse(endpoint.url).hostname or ""
        try:
            schema = self._introspect(host, endpoint.path)
        except Exception as exc:
            return Failed(reason=f"graphql introspection {type(exc).__name__}: {exc}")
        operations = operations_from_introspection(schema) if schema else []
        payload = GraphQLSchema(enabled=bool(schema), operations=tuple(operations),
                                count=len(operations))
        return Done(facts=(Fact(kind="graphql", about=task.node, payload=payload),))


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

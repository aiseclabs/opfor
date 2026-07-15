"""ENRICH-phase HTTP probing, path harvesting, and interface probing capabilities."""

from __future__ import annotations

from urllib.parse import urlparse

from opfor.core import Capability, Done, Fact, Failed, Node, Outcome, Phase, Task, World
from opfor.scenarios.attacksurface.classes.domain.capabilities.common import (
    _coverage_gap,
    _distinct,
    _home_paths,
    _is_static_asset,
    _safe,
)
from opfor.scenarios.attacksurface.classes.domain.sources import (
    cloud_refs_in_text,
    paths_in_javascript,
    robots_entries,
    same_host_path,
    script_sources,
    sitemap_paths,
    urls_in_javascript,
)
from opfor.scenarios.attacksurface.classes.domain.types import (
    Candidates,
    CloudRefs,
    Endpoint,
    HTTP,
)


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
            location=str(result.get("location", "")),
            headers=tuple((str(k), str(v)) for k, v in result.get("headers", ())),
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
        cloud_refs: set[str] = set()

        def add(host: str, path: str) -> None:
            if host and path and path.startswith("/"):
                by_host.setdefault(host, set()).add(path.split("#")[0].split("?")[0])

        home = _safe(lambda: self._fetch_doc(name, "/").get("text", "")) or ""
        cloud_refs.update(cloud_refs_in_text(home))
        for path in _home_paths(home):
            add(name, path)
        for path in _safe(lambda: self._robots(name, addresses)) or []:
            add(name, path)
        for path in _safe(lambda: sitemap_paths(self._fetch_doc(name, "/sitemap.xml").get("text", ""), name)) or []:
            add(name, path)
        for script in script_sources(home, name)[:self._MAX_SCRIPTS]:
            body = _safe(lambda s=script: self._fetch_doc(name, s).get("text", "")) or ""
            cloud_refs.update(cloud_refs_in_text(body))
            for path in paths_in_javascript(body):
                add(name, path)
            for url in urls_in_javascript(body):
                parsed = urlparse(url)
                add(parsed.hostname or "", parsed.path or "/")
        for path in sorted(_safe(lambda: self._wayback(name)) or set()):
            add(name, path)

        facts = [Fact(kind="harvested", about=task.node)]
        if cloud_refs:
            facts.append(Fact(kind="cloud_refs", about=task.node,
                              payload=CloudRefs(urls=tuple(sorted(cloud_refs)))))
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
        cleaned = self._clean(seed, suffixes, prefixes)
        candidates = cleaned[: self._MAX_CANDIDATES]
        baseline = self._baseline(name, addresses)
        endpoints: list[Node] = []
        skipped: list[str] = []
        if baseline.get("status") is None and candidates:
            # the catch-all baseline could not be established, so distinctness cannot filter a
            # blanket-200 or blanket-redirect front, and any endpoint minted here is unfiltered.
            # Say so rather than let the failure pass as a confidently enumerated surface.
            skipped.append("baseline could not be established, endpoint distinctness is unreliable")
        if len(cleaned) > len(candidates):
            # the candidate set is capped, so say how many paths were left unprobed rather
            # than let a bounded probe read as the host's whole surface, invariant 5
            skipped.append(f"{len(cleaned) - len(candidates)} more candidate paths beyond the "
                           f"{self._MAX_CANDIDATES} cap were not probed")
        for path in candidates:
            try:
                result = self._fetch(name, addresses, path)
            except Exception as exc:
                skipped.append(f"{path}: {type(exc).__name__}")
                continue
            status = result.get("status")
            if status is None:
                # a live host gave no answer on this path, a transport failure such as a
                # timeout or a WAF block, not an absent path, so it is a coverage gap rather
                # than a clean negative, invariant 5
                skipped.append(f"{path}: no response")
                continue
            if status == 404:
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
        facts = [Fact(kind="endpoints", about=task.node, yields=tuple(endpoints))]
        gap = _coverage_gap("domain_endpoints", name, len(candidates), skipped)
        if gap is not None:
            facts.append(Fact(kind="coverage_gap", about=task.node, payload=gap))
        return Done(facts=tuple(facts))

    def _clean(self, paths, suffixes, prefixes) -> list[str]:
        """The distinct probeable candidate paths, deduped, static assets dropped. The cap is
        applied by the caller so the number dropped by it can be reported as a coverage gap."""
        out: list[str] = []
        for path in paths:
            if not path or not path.startswith("/") or _is_static_asset(path, suffixes, prefixes):
                continue
            if path not in out:
                out.append(path)
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

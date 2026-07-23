"""ENRICH-phase HTTP probing, path harvesting, and interface probing capabilities."""

from __future__ import annotations

from urllib.parse import urlparse

from opfor.core import Capability, Done, Fact, Node, Outcome, Phase, Task, World
from opfor.scenarios.attacksurface.assets.domain.failures import (
    _coverage_gap,
    _safe,
    net_failed,
)
from opfor.scenarios.attacksurface.assets.domain.responses import (
    _baseline,
    _distinct,
    _home_paths,
    _is_static_asset,
)
from opfor.scenarios.attacksurface.assets.domain.sources.parsers import path_permutations
from opfor.scenarios.attacksurface.assets.domain.sources.http import _BODY_VERSION
from opfor.scenarios.attacksurface.assets.domain.sources import (
    cloud_refs_in_text,
    paths_in_javascript,
    robots_entries,
    same_host_path,
    script_sources,
    sitemap_paths,
    urls_in_javascript,
)
from opfor.scenarios.attacksurface.assets.domain.types import (
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
            return net_failed("http", exc)
        payload = HTTP(
            alive=result.alive,
            status=result.status,
            url=result.url,
            server=result.server,
            title=result.title,
            body=result.body,
            location=result.location,
            headers=result.headers,
        )
        facts = [Fact(kind="http", about=task.node, payload=payload)]
        if not payload.alive and result.reason == "unreachable":
            # the host resolved to a public address but no address answered on either scheme
            # and every attempt timed out, so the run could not reach it, filtered or down.
            # That is a gap in coverage, not a confirmed absence of a web service, so record it
            # rather than let a clean not-alive read as a host that simply serves nothing,
            # invariant 3 and 5. A refused connection is a real negative and records no gap.
            gap = _coverage_gap("domain_http", name, 1, [
                f"{name}: no address answered on either scheme and every attempt timed out, "
                "so the host is filtered or down rather than confirmed to serve no web content"])
            if gap is not None:
                facts.append(Fact(kind="coverage_gap", about=task.node, payload=gap))
        return Done(facts=tuple(facts))


# The disclosure files the probe surfaces, robots and sitemap, owned here with the harvester that
# also reads them to learn paths. They stay in the probe set so a reachable one is presented to the
# model as an endpoint to judge, public by design or not, not only mined for paths.
DISCLOSURE_PROBE_PATHS = ("/robots.txt", "/sitemap.xml")


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

        try:
            home_doc = _safe(lambda: self._fetch_doc(name, "/"))
            home = home_doc.body if home_doc else ""
            cloud_refs.update(cloud_refs_in_text(home))
            for path in _home_paths(home):
                add(name, path)
            for path in _safe(lambda: self._robots(name, addresses)) or []:
                add(name, path)
            for path in _safe(lambda: sitemap_paths(self._fetch_doc(name, "/sitemap.xml").body, name)) or []:
                add(name, path)
            for script in script_sources(home, name)[:self._MAX_SCRIPTS]:
                body = _safe(lambda s=script: self._fetch_doc(name, s).body) or ""
                cloud_refs.update(cloud_refs_in_text(body))
                for path in paths_in_javascript(body):
                    add(name, path)
                for url in urls_in_javascript(body):
                    parsed = urlparse(url)
                    add(parsed.hostname or "", parsed.path or "/")
            for path in sorted(_safe(lambda: self._wayback(name)) or set()):
                add(name, path)
        except Exception as exc:
            # An unexpected harvest error still records the harvested fact plus a coverage gap,
            # rather than a bare crash that leaves no fact. The endpoints rule waits until every
            # live host is harvested, so a factless host would silently suppress interface
            # enumeration for every host while the run still closed, invariant 3 and 5.
            gap = _coverage_gap("domain_harvest", name, 1, [
                f"{name}: harvest failed, {type(exc).__name__}: {exc}, candidate paths for this "
                "host were not gathered"])
            facts = [Fact(kind="harvested", about=task.node)]
            if gap is not None:
                facts.append(Fact(kind="coverage_gap", about=task.node, payload=gap))
            return Done(facts=tuple(facts))

        facts = [Fact(kind="harvested", about=task.node)]
        if home_doc is None or home_doc.reason in ("unreachable", "no-public-address"):
            # The home document is the primary source of candidate paths, so a failure reading
            # it is a coverage gap, not an empty harvest. That failure takes two shapes: a
            # transport gap fetch_document reports as a null status with an unreachable reason,
            # or an unexpected error `_safe` swallowed, leaving home_doc empty. Both are flagged,
            # else a timed-out or erroring home page reads downstream as a host that revealed no
            # paths, the laundering invariant 5 forbids. A reachable empty home has neither shape.
            reason = (home_doc.reason if home_doc else "") or "read failed"
            gap = _coverage_gap("domain_harvest", name, 1, [
                f"{name}: home document {reason}, candidate paths were not gathered"])
            if gap is not None:
                facts.append(Fact(kind="coverage_gap", about=task.node, payload=gap))
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
        if robots.status != 200:
            return []
        paths, sitemaps = robots_entries(robots.body)
        for sitemap in sitemaps[:3]:
            path = same_host_path(sitemap, name)
            if path:
                paths += _safe(lambda p=path: sitemap_paths(self._fetch_doc(name, p).body, name)) or []
        return paths


class PermutePaths(Capability):
    """ENRICH: derive principled path candidates from a host's observed paths.

    Harvesting names the paths a host reveals. This extends that set without a dictionary, it
    derives the parent directories and version-bumped twins of the observed paths and records
    them as candidates the interface probe then confirms against the host's catch-all baseline.
    It reads only paths already gathered and makes no request, so it needs no scope host, the
    probe that follows carries it. It runs once per host, between harvesting and enumeration.
    """

    name = "domain_permute_paths"
    phase = Phase.ENRICH
    osint = True

    def run(self, task: Task, world: World) -> Outcome:
        observed: list[str] = []
        for fact in world.facts("candidates", task.node):
            observed.extend(fact.payload.paths)
        derived = path_permutations(observed)
        facts = [Fact(kind="path_permuted", about=task.node)]
        if derived:
            facts.append(Fact(kind="candidates", about=task.node,
                              payload=Candidates(source="permuted-path", paths=tuple(derived))))
        return Done(facts=tuple(facts))


class ProbeEndpoints(Capability):
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

    def __init__(self, fetch_fn, version_paths=()) -> None:
        self._fetch = fetch_fn
        # Product-declared version endpoints, read to a larger body cap so a version buried deep in
        # a settings document is still reached. Empty when this capability is driven directly in a
        # test, so a bare fetch fake is then always called with the plain signature.
        self._version_paths = frozenset(version_paths)

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
        baseline = _baseline(self._fetch, self._BASELINE_PATHS, name, addresses)
        endpoints: list[Node] = []
        skipped: list[str] = []
        if baseline.status is None and candidates:
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
                if path in self._version_paths:
                    result = self._fetch(name, addresses, path, body_limit=_BODY_VERSION)
                else:
                    result = self._fetch(name, addresses, path)
            except Exception as exc:
                skipped.append(f"{path}: {type(exc).__name__}")
                continue
            status = result.status
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
                url=result.url or f"https://{name}{path}",
                path=path,
                status=status,
                auth_required=status in (401, 403),
                content_type=result.content_type,
                server=result.server,
                title=result.title,
                body=result.body,
                location=result.location,
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


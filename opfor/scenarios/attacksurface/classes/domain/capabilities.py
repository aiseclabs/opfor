"""Domain-class capabilities, each fetches, none judges.

One discovery capability turns the org's hint roots and inventory hosts into domain
nodes. The pivots grow the root set from evidence, a certificate SAN sibling and a
reverse-WHOIS registrant. Subdomains enumerate a root passively. The rest enrich one
domain, resolution, an HTTP probe, path harvesting, interface probing, and the API
surface an exposed specification or an open introspection maps. Certificate transparency,
DNS, and passive sources are public reads, so they are osint. The HTTP probe, harvest, and
interface probes touch the target, so they are scoped recon acts carrying the host for
scope. A source error becomes a loud `Failed`, never an empty `Done`.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from opfor.core import Capability, Done, Fact, Failed, Node, Outcome, Phase, Task, World
from opfor.scenarios.attacksurface import config
from opfor.scenarios.attacksurface.net import registrable_root
from opfor.scenarios.attacksurface.classes.domain.sources import (
    backup_candidates,
    bucket_listable,
    cloud_bucket_from_url,
    cloud_refs_in_text,
    info_from_openapi,
    operations_from_introspection,
    paths_from_openapi,
    paths_in_javascript,
    split_operation,
    robots_entries,
    same_host_path,
    script_sources,
    secrets_in_text,
    sitemap_paths,
    source_map_from_text,
    urls_in_javascript,
)
from opfor.scenarios.attacksurface.classes.domain.types import (
    APISpec,
    BackupHit,
    BackupReport,
    Bucket,
    BucketReport,
    Candidates,
    CloudRefs,
    CoverageGap,
    CVE,
    CVEScan,
    DomainData,
    Endpoint,
    GraphQLSchema,
    HTTP,
    Resolved,
    SecretMatch,
    SecretReport,
    SourceMapLeak,
    SourceMapReport,
    SpecAudit,
    SpecOperation,
)

_LINK = re.compile(r'(?:href|src)\s*=\s*["\']([^"\'#?]+)', re.IGNORECASE)
# Same-host bundles checked for a source map per host, bounded so a bundle-heavy app stays
# a small number of extra reads.
_MAX_SOURCE_MAPS = 12


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
        facts = [Fact(kind="enumerated", about=task.node, yields=found)]
        # A source that stopped at its page cap left subdomains unfetched, so record the
        # gap for triage to report rather than let a bounded set read as the full surface.
        if getattr(names, "truncated", False):
            facts.append(Fact(kind="enumeration_truncated", about=task.node))
        return Done(facts=tuple(facts))


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
        candidates = self._clean(seed, suffixes, prefixes)
        baseline = self._baseline(name, addresses)
        endpoints: list[Node] = []
        skipped: list[str] = []
        for path in candidates:
            try:
                result = self._fetch(name, addresses, path)
            except Exception as exc:
                skipped.append(f"{path}: {type(exc).__name__}")
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
        facts = [Fact(kind="endpoints", about=task.node, yields=tuple(endpoints))]
        gap = _coverage_gap("domain_endpoints", name, len(candidates), skipped)
        if gap is not None:
            facts.append(Fact(kind="coverage_gap", about=task.node, payload=gap))
        return Done(facts=tuple(facts))

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
        title, version = info_from_openapi(parsed)
        payload = APISpec(base=endpoint.url, paths=tuple(paths), count=len(paths),
                          title=title, version=version)
        return Done(facts=(Fact(kind="api_spec", about=task.node, payload=payload),))


class ProbeSpec(Capability):
    """ENRICH: verify the operations an exposed specification declares by a safe read.

    ExpandSpec records what a specification declares, this checks whether the declaration is
    reachable. Each declared GET with a concrete path is fetched once, so an operation is
    never reported reachable on the strength of the document alone. A write method, POST,
    PUT, PATCH, or DELETE, and a templated path are recorded declared but not probed, since
    sending them could change state, so that verdict is deferred to an authorized
    confirmation. Probing is a scoped GET recon act, so it carries the host for scope.
    """

    name = "endpoint_probe_spec"
    phase = Phase.ENRICH
    osint = False

    _MAX_OPERATIONS = 200

    def __init__(self, fetch_fn) -> None:
        self._fetch = fetch_fn

    def run(self, task: Task, world: World) -> Outcome:
        spec = world.latest("api_spec", task.node)
        if spec is None:
            return Failed(reason="no api_spec fact on the target node")
        endpoint = world.node(task.node).payload
        host = urlparse(endpoint.url).hostname or ""
        addresses = self._addresses(world, host)
        baseline = self._baseline(host, addresses)
        operations: list[SpecOperation] = []
        for entry in list(spec.payload.paths)[: self._MAX_OPERATIONS]:
            methods, path = split_operation(entry)
            joined = ",".join(methods)
            if not path.startswith("/") or "{" in path or "}" in path:
                operations.append(SpecOperation(path=path, methods=joined,
                                                reason="templated or relative path, not probed"))
                continue
            if "GET" not in methods:
                operations.append(SpecOperation(path=path, methods=joined,
                                                reason="write operation, not probed without authorization"))
                continue
            try:
                result = self._fetch(host, addresses, path)
            except Exception as exc:
                operations.append(SpecOperation(path=path, methods=joined,
                                                reason=f"probe error {type(exc).__name__}"))
                continue
            status = result.get("status")
            if status is None:
                operations.append(SpecOperation(path=path, methods=joined, reason="no response"))
                continue
            operations.append(SpecOperation(
                path=path, methods=joined, verified=True, status=status,
                auth_required=status in (401, 403),
                distinct=_distinct(result, baseline),
                location=str(result.get("location", "")),
                content_type=str(result.get("content_type", "")),
            ))
        payload = SpecAudit(base=endpoint.url, operations=tuple(operations))
        return Done(facts=(Fact(kind="spec_audit", about=task.node, payload=payload),))

    def _addresses(self, world: World, host: str):
        """The resolved public addresses of the spec's host, read from its domain node."""
        for node in world.nodes("domain"):
            if node.payload.name == host:
                resolved = world.latest("resolved", node.id)
                return resolved.payload.addresses if resolved else ()
        return ()

    def _baseline(self, host, addresses) -> dict:
        for path in Endpoints._BASELINE_PATHS:
            try:
                result = self._fetch(host, addresses, path)
            except Exception:
                continue
            if result.get("status") is not None:
                return result
        return {"status": None, "content_type": "", "body": ""}


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


class CveScan(Capability):
    """ENRICH: identify a live host's product and look up its known vulnerabilities.

    The identify seam names the product, version, and CPE from the host's gathered
    evidence, and the cve seam looks that version up in a public database. Both are
    injected, so this capability holds no model and no knowledge, it gathers raw evidence,
    calls the seams, and records the raw result. Identifying nothing is a clean negative,
    a seam error is a loud Failed, and which CVE matters and how severe is triage's
    judgment. It queries public sources, never the target, so it is osint.
    """

    name = "cve_scan"
    phase = Phase.ENRICH
    osint = True

    def __init__(self, identify_fn, cve_fn) -> None:
        self._identify = identify_fn
        self._cve = cve_fn

    def run(self, task: Task, world: World) -> Outcome:
        host = world.node(task.node)
        try:
            found = self._identify(self._evidence(world, host))
        except Exception as exc:
            return Failed(reason=f"product identification {type(exc).__name__}: {exc}")
        product = str(found.get("product", "")).strip()
        version = str(found.get("version", "")).strip()
        cpe = str(found.get("cpe", "")).strip()
        cves: tuple[CVE, ...] = ()
        if product:
            try:
                raw = self._cve(product, version, cpe)
            except Exception as exc:
                return Failed(reason=f"cve lookup {type(exc).__name__}: {exc}")
            cves = tuple(
                CVE(id=str(c.get("id", "")), cvss=c.get("cvss"),
                    severity=str(c.get("severity", "")), summary=str(c.get("summary", "")),
                    references=tuple(str(u) for u in c.get("references", ())))
                for c in raw if c.get("id"))
        payload = CVEScan(product=product, version=version, cpe=cpe, cves=cves)
        return Done(facts=(Fact(kind="cve_scanned", about=task.node, payload=payload),))

    def _evidence(self, world: World, host) -> str:
        """The host's identification signals as compact text, the HTTP headers, title, and
        server, and the bodies of the paths that name a product or its version."""
        lines = [f"host {host.payload.name}"]
        http = world.latest("http", host.id)
        if http is not None:
            data = http.payload
            if data.status is not None:
                lines.append(f"HTTP {data.status}")
            if data.server:
                lines.append(f"server {data.server}")
            if data.title:
                lines.append(f"title {data.title}")
            if data.location:
                lines.append(f"redirect to {data.location}")
            for header_name, header_value in data.headers:
                lines.append(f"header {header_name}: {header_value}")
            if data.body:
                lines.append(f"body head: {data.body[:600]}")
        for node in world.nodes("endpoint"):
            endpoint = node.payload
            if urlparse(endpoint.url).hostname != host.payload.name:
                continue
            bit = f"path {endpoint.path} HTTP {endpoint.status}"
            if endpoint.content_type:
                bit += f" {endpoint.content_type}"
            if endpoint.body:
                bit += f"\n  body: {endpoint.body[:400]}"
            lines.append(bit)
            title, version = self._spec_info(world, node, endpoint)
            if title or version:
                lines.append(f"  api spec info: title {title!r} version {version!r}")
        return "\n".join(lines)

    def _spec_info(self, world: World, node, endpoint) -> tuple[str, str]:
        """The product title and version an API specification declares, from the parsed
        spec fact when one exists, otherwise from the endpoint's own body head. The `info`
        block sits at the head of an OpenAPI or Swagger document, so the version is present
        the moment the endpoint is probed, before any separate parse runs."""
        spec = world.latest("api_spec", node.id)
        if spec is not None and (spec.payload.title or spec.payload.version):
            return spec.payload.title, spec.payload.version
        try:
            return info_from_openapi(json.loads(endpoint.body or ""))
        except Exception:
            return "", ""


class SourceMapScan(Capability):
    """ENRICH: find reachable JavaScript source maps on a live host.

    A build tool ships `bundle.js.map` next to a bundle, and when it inlines the original
    source in `sourcesContent` the application's source is reconstructable, comments,
    internal paths, and sometimes secrets. The map is skipped as a static asset by the
    interface probe, so this capability derives the map url from each same-host bundle the
    home page loads and reads it. It touches the target, so it is scoped, not osint. It
    reports the raw maps found, whether one is a real leak is triage's judgment.
    """

    name = "source_map_scan"
    phase = Phase.ENRICH
    osint = False

    def __init__(self, fetch_doc_fn) -> None:
        self._fetch_doc = fetch_doc_fn

    def run(self, task: Task, world: World) -> Outcome:
        host = world.node(task.node)
        name = host.payload.name
        try:
            home = self._fetch_doc(name, "/").get("text", "")
            leaks: list[SourceMapLeak] = []
            for bundle in script_sources(home, name)[:_MAX_SOURCE_MAPS]:
                map_path = bundle + ".map"
                text = self._fetch_doc(name, map_path).get("text", "")
                parsed = source_map_from_text(text)
                if parsed is None:
                    continue
                leaks.append(SourceMapLeak(
                    bundle=bundle, url=f"https://{name}{map_path}",
                    sources_count=int(parsed["sources_count"]),
                    has_sources_content=bool(parsed["has_sources_content"]),
                    sample_sources=tuple(parsed["sample_sources"])))
        except Exception as exc:
            return Failed(reason=f"source map scan {type(exc).__name__}: {exc}")
        payload = SourceMapReport(leaks=tuple(leaks))
        return Done(facts=(Fact(kind="source_maps", about=task.node, payload=payload),))


class SecretScan(Capability):
    """ENRICH: scan a live host's JavaScript bundles for secret-like strings.

    A single-page app can ship a hardcoded key or token in a bundle. This reads the same-
    host bundles the home page loads and runs the secret patterns the planner hands it over
    each body, so the capability holds no pattern of its own. A match is redacted, a prefix
    and a length, never the value, so the report and the log never carry the secret. It
    touches the target, so it is scoped, not osint. Whether a match is a live secret or a
    placeholder is triage's judgment.
    """

    name = "secret_scan"
    phase = Phase.ENRICH
    osint = False

    def __init__(self, fetch_doc_fn) -> None:
        self._fetch_doc = fetch_doc_fn

    def run(self, task: Task, world: World) -> Outcome:
        host = world.node(task.node)
        name = host.payload.name
        patterns = task.params.get("patterns", [])
        try:
            home = self._fetch_doc(name, "/").get("text", "")
            matches: list[SecretMatch] = []
            for bundle in script_sources(home, name)[:_MAX_SOURCE_MAPS]:
                body = self._fetch_doc(name, bundle).get("text", "")
                for found in secrets_in_text(body, patterns):
                    matches.append(SecretMatch(pattern=found["pattern"], note=found["note"],
                                               bundle=bundle, sample=found["sample"]))
        except Exception as exc:
            return Failed(reason=f"secret scan {type(exc).__name__}: {exc}")
        payload = SecretReport(matches=tuple(matches))
        return Done(facts=(Fact(kind="secrets_in_js", about=task.node, payload=payload),))


class BackupScan(Capability):
    """ENRICH: probe for backup and editor-artifact twins of a host's observed files.

    An editor or a deploy leaves `config.php.bak`, a vim swap `.config.php.swp`, or an
    archive `config.zip` beside the file it serves, and that twin often returns the source
    the live file hides behind an interpreter. The twin names are derived from the files this
    host actually revealed, its reached endpoints and the paths its home page harvested, so
    the probe follows the real surface rather than a fixed guess list. The name templates are
    handed in, so the capability holds no list of its own. Probing is a scoped recon act, GET
    only, so it carries the host for scope. It reports the twins that answered, whether one is
    a real source leak is triage's judgment.
    """

    name = "backup_scan"
    phase = Phase.ENRICH
    osint = False

    _MAX_FILES = 20
    _MAX_CANDIDATES = 150
    # Unlikely twin paths, probed first to learn how the host answers a backup name that does
    # not exist, the same catch-all guard the interface probe uses.
    _BASELINE_PATHS = ("/opfor-baseline-6f3a9c2e.bak", "/does-not-exist-8b1d.old")

    def __init__(self, fetch_fn) -> None:
        self._fetch = fetch_fn

    def run(self, task: Task, world: World) -> Outcome:
        host = world.node(task.node)
        name = host.payload.name
        resolved = world.latest("resolved", task.node)
        addresses = resolved.payload.addresses if resolved else ()
        append = tuple(task.params.get("append") or ())
        rename = tuple(task.params.get("rename") or ())
        swap = tuple(task.params.get("swap") or ())
        candidates = self._candidates(world, host, append, rename, swap)
        baseline = self._baseline(name, addresses)
        hits: list[BackupHit] = []
        skipped: list[str] = []
        for path in candidates:
            try:
                result = self._fetch(name, addresses, path)
            except Exception as exc:
                skipped.append(f"{path}: {type(exc).__name__}")
                continue
            status = result.get("status")
            if status is None or status == 404:
                continue
            if not _distinct(result, baseline):
                continue
            hits.append(BackupHit(
                url=result.get("url", f"https://{name}{path}"),
                path=path,
                status=status,
                content_type=str(result.get("content_type", "")),
                size=len(result.get("body", "")),
            ))
        facts = [Fact(kind="backups", about=task.node, payload=BackupReport(hits=tuple(hits)))]
        gap = _coverage_gap("backup_scan", name, len(candidates), skipped)
        if gap is not None:
            facts.append(Fact(kind="coverage_gap", about=task.node, payload=gap))
        return Done(facts=tuple(facts))

    def _candidates(self, world: World, host, append, rename, swap) -> list[str]:
        """The twin paths to probe, derived from the file-like paths this host revealed, its
        reached endpoints and its harvested candidates, deduped and capped."""
        files: list[str] = []

        def add_file(path: str) -> None:
            path = (path or "").split("?")[0].split("#")[0]
            if not path.startswith("/") or path.endswith("/"):
                return
            if "." not in path.rsplit("/", 1)[-1]:
                return
            if path not in files:
                files.append(path)

        for node in world.nodes("endpoint"):
            if urlparse(node.payload.url).hostname == host.payload.name:
                add_file(node.payload.path)
        for fact in world.facts("candidates", host.id):
            for path in fact.payload.paths:
                add_file(path)

        out: list[str] = []
        for path in files[:self._MAX_FILES]:
            for candidate in backup_candidates(path, append=append, rename=rename, swap=swap):
                if candidate not in out:
                    out.append(candidate)
                if len(out) >= self._MAX_CANDIDATES:
                    return out
        return out

    def _baseline(self, name, addresses) -> dict:
        """The host's answer to a backup name that does not exist, its catch-all signature."""
        for path in self._BASELINE_PATHS:
            try:
                result = self._fetch(name, addresses, path)
            except Exception:
                continue
            if result.get("status") is not None:
                return result
        return {"status": None, "content_type": "", "body": ""}


class BucketScan(Capability):
    """ENRICH: check cloud object-storage buckets the target reveals, for public access.

    A public S3, GCS, or Azure bucket often holds the backups, dumps, or logs the target
    never meant to expose. The buckets are discovered from evidence, never guessed by name,
    a url the target's own pages reference and a subdomain CNAME that points at a provider,
    both already in the world. Each discovered bucket is checked anonymously against its
    provider's public list endpoint. It reads only public cloud endpoints, never the target's
    own server and never with a credential, so it is osint. It records whether each bucket is
    listable or private, whether a listable bucket holds sensitive objects is triage's
    judgment.
    """

    name = "bucket_scan"
    phase = Phase.ENRICH
    osint = True

    def __init__(self, probe_url_fn) -> None:
        self._probe = probe_url_fn

    def run(self, task: Task, world: World) -> Outcome:
        discovered = self._discovered(world)
        buckets: list[Bucket] = []
        skipped: list[str] = []
        for key in sorted(discovered):
            found, evidence = discovered[key]
            try:
                result = self._probe(found["list_url"])
            except Exception as exc:
                skipped.append(f"{key}: {type(exc).__name__}")
                continue
            status = result.get("status")
            if status == 200 and bucket_listable(result.get("body", "")):
                state = "listable"
            elif status in (401, 403):
                state = "private"
            else:
                continue
            buckets.append(Bucket(name=found["bucket"], provider=found["provider"],
                                  url=found["list_url"], state=state, evidence=evidence,
                                  status=status))
        facts = [Fact(kind="buckets", about=task.node, payload=BucketReport(buckets=tuple(buckets)))]
        gap = _coverage_gap("bucket_scan", "cloud storage", len(discovered), skipped)
        if gap is not None:
            facts.append(Fact(kind="coverage_gap", about=task.node, payload=gap))
        return Done(facts=tuple(facts))

    def _discovered(self, world: World) -> dict:
        """The buckets the target revealed, keyed by provider and name so a bucket referenced
        many times is checked once. Evidence is a url the pages reference or a subdomain CNAME
        that points at the provider, so a bucket here is observed, never guessed."""
        found: dict[str, tuple[dict, str]] = {}

        def record(reference: str, evidence: str) -> None:
            bucket = cloud_bucket_from_url(reference)
            if bucket is None:
                return
            found.setdefault(f"{bucket['provider']}:{bucket['bucket']}", (bucket, evidence))

        for fact in world.facts("cloud_refs"):
            host = world.node(fact.about)
            source = host.payload.name if host else fact.about
            for url in fact.payload.urls:
                record(url, f"referenced by {source}")
        for fact in world.facts("resolved"):
            host = world.node(fact.about)
            source = host.payload.name if host else fact.about
            for cname in fact.payload.cnames:
                record(cname, f"CNAME from {source}")
        return found


_MAX_GAP_REASONS = 5


def _coverage_gap(scan: str, host: str, attempted: int, skipped: list[str]) -> CoverageGap | None:
    """A coverage gap payload when a per-item scan skipped items on errors, else None. So a
    scan that dropped items keeps the drop loud rather than passing a partial surface off as
    a clean negative, invariant 5. The reasons are a bounded sample so the fact stays small."""
    if not skipped:
        return None
    return CoverageGap(scan=scan, host=host, attempted=attempted, failed=len(skipped),
                       reasons=tuple(skipped[:_MAX_GAP_REASONS]))


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

"""Attack-surface triage: judge discovered assets into ranked findings, per class.

The judge reads the enriched world and the scenario's knowledge, and mints a finding
for each asset worth an operator's attention. For a domain it reports a likely
takeover as HIGH, a live non-production or admin surface as MEDIUM, and a dangling
name that still has a certificate as LOW. For a GitHub org it reports the org as an
INFO inventory line with its repo count, the reachable code surface under the name. A
plain live name is inventory, not a finding, so the report stays signal, and the full
inventory lives in the world for the operator to dump.

The takeover signatures and interesting-name keywords are knowledge, loaded from data
here in triage. No capability reads them.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from opfor.core import Finding, Triage, World
from opfor.scenarios.attacksurface.types import DomainData


class SurfaceTriage(Triage):
    # Paths expected to be public, so a reachable one is inventory, not a finding.
    _EXPECTED_PUBLIC = frozenset({"/robots.txt", "/sitemap.xml", "/.well-known/security.txt"})
    # A static asset served by a web app is not an interface. A single-page app links dozens
    # of hashed bundles from its home page, so counting each as an unauthenticated interface
    # would bury the real routes. A matched exposure detector still fires, this only quiets
    # the plain inventory line for an asset.
    _STATIC_SUFFIXES = (
        ".js", ".mjs", ".css", ".map", ".ico", ".png", ".jpg", ".jpeg", ".gif", ".svg",
        ".webp", ".avif", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".webm",
    )
    _STATIC_PREFIXES = ("/_next/static/", "/static/", "/assets/", "/_nuxt/")

    def __init__(self, content_root: str | Path) -> None:
        knowledge = Path(content_root) / "knowledge"
        takeover = yaml.safe_load((knowledge / "takeover.yaml").read_text(encoding="utf-8")) or {}
        interesting = yaml.safe_load((knowledge / "interesting.yaml").read_text(encoding="utf-8")) or {}
        exposures = yaml.safe_load((knowledge / "exposures.yaml").read_text(encoding="utf-8")) or {}
        self._takeover = [
            (str(e["service"]), str(e["signature"]).lower())
            for e in (takeover.get("services") or [])
        ]
        self._keywords = [str(k).lower() for k in (interesting.get("keywords") or [])]
        self._detectors = list(exposures.get("detectors") or [])
        # Precompile the body regex a detector may carry, so a match is a strong signal
        # rather than a bare 200 an app returns for every path.
        for detector in self._detectors:
            if detector.get("body_regex"):
                detector["_body_re"] = re.compile(str(detector["body_regex"]), re.IGNORECASE)

    def judge(self, world: World) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._roots(world))
        findings.extend(self._domains(world))
        findings.extend(self._endpoints(world))
        findings.extend(self._interfaces(world))
        findings.extend(self._github(world))
        return findings

    def _interfaces(self, world: World) -> list[Finding]:
        """Report the API surface an app declared about itself, a parsed specification and
        an open GraphQL introspection, each mapping a whole unauthenticated interface."""
        out: list[Finding] = []
        for fact in world.facts("api_spec"):
            spec = fact.payload
            if spec.count == 0:
                continue
            out.append(Finding(
                id=f"finding:api_surface:{spec.base}",
                title=f"Unauthenticated API specification maps {spec.count} operation(s)",
                severity="MEDIUM",
                where=spec.base,
                evidence=f"parsed the exposed specification, it declares {spec.count} operations",
                data={"kind": "api_surface", "count": spec.count, "paths": list(spec.paths)[:200],
                      "poc": f"curl -s {spec.base} , then exercise the declared operations it maps"},
            ))
        for fact in world.facts("graphql"):
            schema = fact.payload
            # Introspection that named no operation is not usable introspection, an endpoint
            # can answer a POST yet refuse the schema, so this reports only a real surface.
            if not schema.enabled or schema.count == 0:
                continue
            node = world.node(fact.about)
            url = node.payload.url if node else "(graphql)"
            out.append(Finding(
                id=f"finding:graphql:{url}",
                title=f"GraphQL introspection enabled, {schema.count} operation(s)",
                severity="MEDIUM",
                where=url,
                evidence="introspection returned the schema, which maps the whole API",
                data={"kind": "graphql", "count": schema.count,
                      "operations": list(schema.operations)[:200],
                      "poc": f"curl -s -X POST {url} -H 'content-type: application/json' "
                             "-d '{\"query\":\"{__schema{queryType{name}}}\"}'"},
            ))
        return out

    def _roots(self, world: World) -> list[Finding]:
        """Report each associated root the run discovered beyond the operator's hints,
        an INFO inventory line carrying the evidence that attributes it to the target."""
        out: list[Finding] = []
        for node in world.nodes("domain"):
            data = node.payload
            if data.name != data.root or data.source == "hint":
                continue
            out.append(self._finding("root", data.root, "INFO",
                f"Associated root domain {data.root}",
                data.evidence or "discovered as an associated root",
                {"source": data.source, "confidence": data.confidence}))
        return out

    def _endpoints(self, world: World) -> list[Finding]:
        """Judge each unauthenticated interface: a matched detector is an exposure with a
        PoC, an unmatched one is inventory, the unauthenticated surface worth confirming."""
        out: list[Finding] = []
        for node in world.nodes("endpoint"):
            ep = node.payload
            if ep.auth_required:
                continue
            detector = self._match(ep)
            if detector is not None:
                out.append(Finding(
                    id=f"finding:exposure:{ep.url}",
                    title=str(detector["title"]),
                    severity=str(detector["severity"]),
                    where=ep.url,
                    evidence=f"HTTP {ep.status} at {ep.path}, matched detector {detector['id']}",
                    data={"kind": "exposure", "detector": detector["id"], "status": ep.status,
                          "poc": str(detector.get("poc", "")).format(url=ep.url)},
                ))
            elif (ep.path not in self._EXPECTED_PUBLIC and not self._is_static_asset(ep.path)
                  and not self._is_protected(ep)):
                out.append(Finding(
                    id=f"finding:unauth:{ep.url}",
                    title=f"Unauthenticated interface reachable at {ep.path}",
                    severity="INFO",
                    where=ep.url,
                    evidence=f"HTTP {ep.status} without auth, server {ep.server or 'unknown'}",
                    data={"kind": "unauth", "status": ep.status,
                          "poc": f"curl -s {ep.url} , confirm this should be public"},
                ))
        return out

    # A redirect whose target names a login flow is the app enforcing auth, not an open
    # interface, and a body carrying a plain refusal is the same. These suppress the weak
    # INFO line, they never suppress a detector match, which asserts an exposure on content.
    _LOGIN_LOCATION = ("login", "signin", "sign-in", "/sso", "/auth", "/account", "oauth", "openid")
    _AUTH_BODY = (
        "unauthorized", "forbidden", "authentication required", "access denied",
        "not authorized", "please log in", "please sign in", "you must be logged in",
        "requires authentication", "login required",
    )

    def _is_protected(self, ep) -> bool:
        """Whether a reachable response is really the app enforcing auth rather than an open
        interface, a redirect to a login flow or a body that plainly refuses access."""
        if ep.status is not None and 300 <= ep.status < 400:
            location = (ep.location or "").lower()
            if any(hint in location for hint in self._LOGIN_LOCATION):
                return True
        body = ep.body or ""
        return any(signal in body for signal in self._AUTH_BODY)

    def _is_static_asset(self, path: str) -> bool:
        """Whether a path is a web app's static asset rather than an interface."""
        lowered = path.lower().split("?")[0]
        return (lowered.endswith(self._STATIC_SUFFIXES)
                or any(lowered.startswith(prefix) for prefix in self._STATIC_PREFIXES))

    def _match(self, ep) -> dict | None:
        for detector in self._detectors:
            path = str(detector.get("path", ""))
            if path and ep.path != path and not ep.path.endswith(path):
                continue
            content_type = detector.get("content_type")
            if content_type and str(content_type) not in (ep.content_type or "").lower():
                continue
            contains = detector.get("body_contains")
            if contains and str(contains) not in ep.body:
                continue
            absent = detector.get("body_absent")
            if absent and str(absent) in ep.body:
                continue
            regex = detector.get("_body_re")
            if regex is not None and not regex.search(ep.body):
                continue
            # A detector must assert something beyond the path, or an app that answers for
            # every path would match it.
            if not (contains or detector.get("body_regex") or content_type):
                continue
            return detector
        return None

    def _domains(self, world: World) -> list[Finding]:
        out: list[Finding] = []
        domains = world.nodes("domain")
        # A dangling call rests on our resolver working. When almost nothing resolves the
        # resolver is the problem, not the whole zone, so calling those names dangling
        # would be a wall of false positives. Above a high failure rate, suppress the
        # dangling and probing results and say the run is incomplete, a loud caveat rather
        # than a guess. This trades a little recall for not lying, and it says so.
        unresolved = sum(
            1 for n in domains
            if not ((r := world.latest("resolved", n.id)) is not None and r.payload.resolvable)
        )
        if domains and unresolved / len(domains) >= 0.9:
            return [Finding(
                id="finding:incomplete:resolution",
                title=f"Resolution unavailable, {unresolved} of {len(domains)} names did not resolve",
                severity="INFO",
                where="(resolver)",
                evidence="almost nothing resolved, so probing and dangling checks were "
                         "suppressed to avoid false positives, rerun from a host with a "
                         "working resolver to assess reachability",
                data={"kind": "incomplete", "unresolved": unresolved, "domains": len(domains)},
            )]
        for node in domains:
            data = node.payload
            http = world.latest("http", node.id)
            resolved = world.latest("resolved", node.id)
            http_data = http.payload if http else None
            resolved_data = resolved.payload if resolved else None

            service = self._takeover_service(http_data)
            if service is not None:
                out.append(self._finding("takeover", data.name, "HIGH",
                    f"Possible subdomain takeover via {service}",
                    f"live host answers with the {service} unclaimed-service page",
                    {"root": data.root, "source": data.source}))
            elif resolved_data is not None and not resolved_data.resolvable and data.source == "passive":
                out.append(self._finding("dangling", data.name, "LOW",
                    "Dangling name, seen passively but it does not resolve",
                    "a passive source names this host yet DNS returns no address, verify for takeover",
                    {"root": data.root, "source": data.source}))

            keyword = self._interesting(data)
            if http_data is not None and http_data.alive and keyword is not None:
                out.append(self._finding("exposed", data.name, "MEDIUM",
                    f"Exposed {keyword} surface",
                    self._surface_evidence(keyword, http_data),
                    {"root": data.root, "status": http_data.status}))
        return out

    def _github(self, world: World) -> list[Finding]:
        out: list[Finding] = []
        for node in world.nodes("github_org"):
            login = node.payload.login
            repos = [r for r in world.nodes("github_repo") if r.id.startswith(f"github_repo:{login}/")]
            out.append(self._finding("github_org", login, "INFO",
                f"GitHub org {login}, {len(repos)} public repo(s)",
                f"reachable code surface at {node.payload.url}",
                {"login": login, "repos": len(repos), "url": node.payload.url}))
        return out

    def _takeover_service(self, http) -> str | None:
        if http is None or not http.alive or not http.body:
            return None
        for service, signature in self._takeover:
            if signature in http.body:
                return service
        return None

    def _interesting(self, data: DomainData) -> str | None:
        sub = data.name[:-(len(data.root) + 1)] if data.name.endswith("." + data.root) else data.name
        for keyword in self._keywords:
            if keyword in sub:
                return keyword
        return None

    @staticmethod
    def _surface_evidence(keyword: str, http) -> str:
        bits = [f"name suggests {keyword}", f"HTTP {http.status}"]
        if http.title:
            bits.append(f"title '{http.title}'")
        if http.server:
            bits.append(f"server {http.server}")
        return ", ".join(bits)

    @staticmethod
    def _finding(kind: str, where: str, severity: str, title: str, evidence: str, extra: dict) -> Finding:
        return Finding(
            id=f"finding:{kind}:{where}",
            title=title,
            severity=severity,
            where=where,
            evidence=evidence,
            data={"kind": kind, **extra},
        )

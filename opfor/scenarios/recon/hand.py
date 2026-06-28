"""The recon hand. Maps an attack surface from a company's seed domains.

Actions, all reach-and-read, none decides anything. `subdomains` aggregates many
passive sources, certificate transparency and passive DNS, and merges them,
because no single source is complete. `resolve` checks DNS. `get` is a single
light HTTP read of a domain root, enough to tell what is alive and what stack it
runs. `discover_roots` looks for candidate root domains from an org keyword. The
surface grows: querying a root yields many domains, each a new thing to probe.
Judgment, which domain is interesting or exposed, is left to the brain.
"""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

_RESOLVE_WORKERS = 50

from opfor.engine.graph import SituationGraph
from opfor.model import (
    Domain,
    Entrypoint,
    Fact,
    Finding,
    Host,
    Observation,
    Service,
    Target,
    Technology,
)
from opfor.plugins.base import Hand
from opfor.scenarios.recon.sources import SUBDOMAIN_SOURCES

_BODY_CAP = 2048
_GET_TIMEOUT = 8
_ROOT_TIMEOUT = 30

# Response headers that name a server-side or framework technology.
_TECH_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator")


def _real_resolve(domain: str) -> list[str]:
    """Resolve a domain to its addresses. Empty list means it does not resolve."""
    infos = socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
    return sorted({ai[4][0] for ai in infos})


# Two-label suffixes where the registrable domain needs three labels.
_TWO_LABEL_TLDS = {
    "co.uk", "com.cn", "com.hk", "com.sg", "com.tw", "co.jp", "com.au", "co.in"
}


def _apex(name: str) -> str:
    """Best-effort registrable domain from a hostname."""
    name = name.strip().lstrip("*.").lower()
    parts = name.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _TWO_LABEL_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else name


def _real_root_search(keyword: str) -> list[str]:
    """Best-effort candidate root domains for a keyword, from crt.sh.

    This is deliberately just a lead generator. Name based search is noisy, it
    misses owned domains that do not contain the keyword and it picks up
    unrelated holders of the same string. The operator confirms which candidates
    are really in scope, the tool never asserts ownership.
    """
    url = f"https://crt.sh/?q={urllib.parse.quote(keyword)}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "opfor-recon"})
    with urllib.request.urlopen(req, timeout=_ROOT_TIMEOUT) as resp:
        rows = json.loads(resp.read().decode("utf-8", "replace"))
    roots: set[str] = set()
    for row in rows:
        for raw in str(row.get("name_value", "")).splitlines():
            name = raw.strip().lstrip("*.").lower()
            apex = _apex(name)
            # Keep only apexes that look like a domain and carry the keyword.
            if "." in apex and keyword.lower() in apex:
                roots.add(apex)
    return sorted(roots)


class ReconHand(Hand):
    name = "recon"

    def __init__(
        self,
        subdomain_sources: list[tuple[str, Callable[[str], list[str]]]] | None = None,
        resolve_fn: Callable[[str], list[str]] | None = None,
        root_search: Callable[[str], list[str]] | None = None,
        checks: list[dict] | None = None,
    ) -> None:
        # All injectable so the hand is unit-testable without network access.
        self._sources = subdomain_sources if subdomain_sources is not None else SUBDOMAIN_SOURCES
        self._resolve_fn = resolve_fn or _real_resolve
        self._root_search = root_search or _real_root_search
        # Security checks are data the scenario wires in, the hand stays a
        # generic matcher engine that applies whatever it is given (nuclei model).
        self._checks = checks or []

    # --- enumerate --------------------------------------------------------

    def enumerate(self, target: Target, graph: SituationGraph) -> list[Entrypoint]:
        eps: list[Entrypoint] = []
        # From an org seed, look for candidate root domains. Passive OSINT.
        if target.kind == "org":
            eps.append(self._discover_ep(target.id))
        # One passive sweep per confirmed seed root. The sources return every
        # depth, so we do not recurse, which keeps the surface bounded.
        if target.kind == "domain":
            eps.append(self._subdomains_ep(target.id))
        hosts = graph.entities("host")
        attempted = {h.props.get("domain") for h in hosts}  # type: ignore[attr-defined]
        live = {h.props.get("domain") for h in hosts if h.props.get("live")}  # type: ignore[attr-defined]
        known = self._known_domains(graph)
        # Resolve everything not yet attempted in ONE concurrent batch, so a few
        # hundred names cost one fast step instead of hundreds of slow ticks.
        pending = sorted(n for n in known if n not in attempted)
        if pending:
            eps.append(self._resolve_batch_ep(pending, len(hosts)))
        # Only spend an HTTP probe on names that actually resolved.
        for name, url in known.items():
            if name in live:
                eps.append(self._get_ep(name, url))
        # Security checks run only on services we confirmed are live.
        for svc in graph.entities("service"):
            for check in self._checks:
                eps.append(self._check_ep(svc.id, svc.props.get("domain"), check))  # type: ignore[attr-defined]
        return eps

    def _known_domains(self, graph: SituationGraph) -> dict[str, str]:
        # Confirmed seed roots plus subdomains discovered under them. Candidate
        # roots are deliberately excluded, they are not expanded until an
        # operator confirms them by adding them to scope and seeding them.
        domains: dict[str, str] = {}
        for t in graph.targets():
            if t.kind == "domain":
                domains[t.id] = t.props.get("url") or f"https://{t.id}/"
        for d in graph.entities("domain"):
            if d.props.get("candidate"):  # type: ignore[attr-defined]
                continue
            domains[d.id] = d.props.get("url") or f"https://{d.id}/"  # type: ignore[attr-defined]
        return domains

    def _discover_ep(self, org: str) -> Entrypoint:
        return Entrypoint(
            id=f"discover::{org}",
            target_id=org,
            kind="org-roots",
            ref=org,
            actions=("discover_roots",),
            props={
                "org": org,
                "osint": True,
                "scope_host": org,
                "action_tiers": {"discover_roots": "recon"},
            },
        )

    def _resolve_batch_ep(self, domains: list[str], seq: int) -> Entrypoint:
        return Entrypoint(
            id=f"resolve-batch::{seq}",
            target_id="(batch)",
            kind="dns-batch",
            ref=f"{len(domains)} names",
            actions=("resolve_all",),
            props={
                # Passive DNS over names already discovered under confirmed roots.
                "domains": domains,
                "osint": True,
                "scope_host": "(batch)",
                "action_tiers": {"resolve_all": "recon"},
            },
        )

    def _subdomains_ep(self, domain: str) -> Entrypoint:
        return Entrypoint(
            id=f"subdomains::{domain}",
            target_id=domain,
            kind="subdomain-sweep",
            ref=domain,
            actions=("subdomains",),
            props={
                "domain": domain,
                "scope_host": domain,
                "action_tiers": {"subdomains": "recon"},
            },
        )

    def _check_ep(self, service_url: str, domain: str, check: dict) -> Entrypoint:
        cid = check["id"]
        return Entrypoint(
            id=f"check::{service_url}::{cid}",
            target_id=domain,
            kind="security-check",
            ref=f"{cid} {check.get('path', '/')}",
            actions=("check",),
            props={
                "url": service_url,
                "path": check.get("path", "/"),
                "domain": domain,
                "check": check,
                "scope_host": domain,
                "action_tiers": {"check": "probe"},
            },
        )

    def _get_ep(self, domain: str, url: str) -> Entrypoint:
        return Entrypoint(
            id=f"get::{domain}",
            target_id=domain,
            kind="http-root",
            ref=url,
            actions=("get",),
            props={
                "domain": domain,
                "url": url,
                "scope_host": domain,
                "action_tiers": {"get": "probe"},
            },
        )

    # --- act --------------------------------------------------------------

    def act(self, entrypoint: Entrypoint, action: str, params: dict) -> Observation:
        if action == "discover_roots":
            return self._act_discover(entrypoint)
        if action == "subdomains":
            return self._act_subdomains(entrypoint)
        if action == "resolve_all":
            return self._act_resolve_all(entrypoint)
        if action == "get":
            return self._act_get(entrypoint)
        if action == "check":
            return self._act_check(entrypoint)
        raise ValueError(
            f"recon hand supports discover_roots, subdomains, resolve_all, get, check, got: {action}"
        )

    def _act_check(self, entrypoint: Entrypoint) -> Observation:
        base = entrypoint.props["url"]
        path = entrypoint.props["path"]
        check = entrypoint.props["check"]
        domain = entrypoint.props["domain"]
        url = urllib.parse.urljoin(base, path.lstrip("/"))
        req = urllib.request.Request(url, method="GET")
        common = {"domain": domain, "url": url, "check": check}
        try:
            with urllib.request.urlopen(req, timeout=_GET_TIMEOUT) as resp:
                body = resp.read(_BODY_CAP).decode("utf-8", "replace")
                raw = {**common, "status": resp.status, "headers": dict(resp.headers.items()), "body": body}
        except urllib.error.HTTPError as exc:
            body = exc.read(_BODY_CAP).decode("utf-8", "replace")
            raw = {
                **common,
                "status": exc.code,
                "headers": dict(exc.headers.items()) if exc.headers else {},
                "body": body,
            }
        except urllib.error.URLError as exc:
            raw = {**common, "status": None, "error": str(exc.reason)}
        return Observation(entrypoint_id=entrypoint.id, action="check", raw=raw)

    def _act_subdomains(self, entrypoint: Entrypoint) -> Observation:
        """Query every passive source and merge. One source failing is fine."""
        domain = entrypoint.props["domain"]
        names: set[str] = set()
        report: dict[str, object] = {}
        for label, fetch in self._sources:
            try:
                got = fetch(domain)
                names.update(got)
                report[label] = len(got)
            except Exception as exc:  # any source may flake, keep going
                report[label] = f"error:{type(exc).__name__}"
        return Observation(
            entrypoint_id=entrypoint.id,
            action="subdomains",
            raw={"domain": domain, "names": sorted(names), "sources": report},
        )

    def _act_discover(self, entrypoint: Entrypoint) -> Observation:
        org = entrypoint.props["org"]
        try:
            roots = self._root_search(org)
            raw = {"org": org, "roots": roots}
        except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as exc:
            raw = {"org": org, "error": str(exc)}
        return Observation(entrypoint_id=entrypoint.id, action="discover_roots", raw=raw)

    def _act_resolve_all(self, entrypoint: Entrypoint) -> Observation:
        domains = entrypoint.props["domains"]

        def one(domain: str) -> tuple[str, list[str]]:
            try:
                return domain, list(self._resolve_fn(domain))
            except OSError:
                return domain, []

        with ThreadPoolExecutor(max_workers=_RESOLVE_WORKERS) as pool:
            results = dict(pool.map(one, domains))
        return Observation(
            entrypoint_id=entrypoint.id, action="resolve_all", raw={"results": results}
        )

    def _act_get(self, entrypoint: Entrypoint) -> Observation:
        url = entrypoint.props["url"]
        domain = entrypoint.props["domain"]
        req = urllib.request.Request(url, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=_GET_TIMEOUT) as resp:
                resp.read(_BODY_CAP)
                raw = {
                    "domain": domain,
                    "url": url,
                    "status": resp.status,
                    "headers": dict(resp.headers.items()),
                }
        except urllib.error.HTTPError as exc:
            raw = {
                "domain": domain,
                "url": url,
                "status": exc.code,
                "headers": dict(exc.headers.items()) if exc.headers else {},
            }
        except urllib.error.URLError as exc:
            raw = {"domain": domain, "url": url, "status": None, "error": str(exc.reason)}
        return Observation(entrypoint_id=entrypoint.id, action="get", raw=raw)

    # --- normalize --------------------------------------------------------

    def normalize(self, observation: Observation) -> list[Fact]:
        if observation.action == "discover_roots":
            return self._norm_discover(observation)
        if observation.action == "subdomains":
            return self._norm_subdomains(observation)
        if observation.action == "resolve_all":
            return self._norm_resolve_all(observation)
        if observation.action == "get":
            return self._norm_get(observation)
        if observation.action == "check":
            return self._norm_check(observation)
        return []

    def _norm_check(self, obs: Observation) -> list[Fact]:
        raw = obs.raw
        check = raw.get("check", {})
        cid = check.get("id", "check")
        if raw.get("error"):
            return [Fact(kind="check-failed", about=obs.entrypoint_id, data={"id": cid, "error": raw["error"]})]
        match = check.get("match", {})
        hit = True
        if "status" in match and raw.get("status") != match["status"]:
            hit = False
        if "body_contains" in match:
            body = (raw.get("body") or "").lower()
            if str(match["body_contains"]).lower() not in body:
                hit = False
        if "header_missing" in match:
            present = {k.lower() for k in (raw.get("headers") or {})}
            if str(match["header_missing"]).lower() in present:
                hit = False
        if not hit:
            return [Fact(kind="check-clean", about=obs.entrypoint_id, data={"id": cid})]
        finding = Finding(
            id=f"finding:{cid}:{raw.get('domain')}",
            props={
                "title": check.get("title", cid),
                "severity": check.get("severity", "info"),
                "domain": raw.get("domain"),
                "url": raw.get("url"),
                "evidence": f"{cid} matched at {raw.get('url')} (status {raw.get('status')})",
            },
        )
        return [
            Fact(
                kind="vuln",
                about=obs.entrypoint_id,
                data={"id": cid, "severity": check.get("severity")},
                yields=(finding,),
            )
        ]

    def _norm_discover(self, obs: Observation) -> list[Fact]:
        raw = obs.raw
        if raw.get("error"):
            return [Fact(kind="discover-failed", about=obs.entrypoint_id, data={"error": raw["error"]})]
        org = raw["org"]
        # Candidate roots only, flagged so they are recorded but not expanded.
        candidates = tuple(
            Domain(id=root, props={"candidate": True, "org": org, "source": "crtsh-org"})
            for root in raw.get("roots", [])
        )
        return [
            Fact(
                kind="candidate-roots",
                about=obs.entrypoint_id,
                data={"org": org, "count": len(candidates)},
                yields=candidates,
            )
        ]

    def _norm_resolve_all(self, obs: Observation) -> list[Fact]:
        # One Host per domain, live or dead, so a dead name is recorded and never
        # retried. Only live hosts carry addresses and earn an HTTP probe.
        results = obs.raw.get("results", {})
        hosts = tuple(
            Host(id=f"host:{d}", props={"domain": d, "ips": ips, "live": bool(ips)})
            for d, ips in results.items()
        )
        live = sum(1 for h in hosts if h.props["live"])
        return [
            Fact(
                kind="resolved-batch",
                about=obs.entrypoint_id,
                data={"resolved": len(hosts), "live": live},
                yields=hosts,
            )
        ]

    def _norm_subdomains(self, obs: Observation) -> list[Fact]:
        raw = obs.raw
        root = raw["domain"]
        # Clean and dedupe across all sources, then keep only names actually under
        # the queried root. This is data hygiene, not a scope decision.
        clean: set[str] = set()
        for name in raw.get("names", []):
            n = str(name).strip().lstrip("*.").lower()
            if n and (n == root or n.endswith("." + root)):
                clean.add(n)
        discovered = tuple(
            Domain(id=n, props={"parent": root, "depth": n.count(".")})
            for n in sorted(clean)
        )
        return [
            Fact(
                kind="subdomains-found",
                about=obs.entrypoint_id,
                data={"root": root, "count": len(discovered), "sources": raw.get("sources", {})},
                yields=discovered,
            )
        ]

    def _norm_get(self, obs: Observation) -> list[Fact]:
        raw = obs.raw
        if raw.get("error"):
            return [
                Fact(
                    kind="request-failed",
                    about=obs.entrypoint_id,
                    data={"domain": raw.get("domain"), "error": raw["error"]},
                )
            ]
        url = raw["url"]
        headers = raw.get("headers", {})
        yields: list[object] = [
            Service(
                id=url,
                props={"domain": raw.get("domain"), "status": raw.get("status")},
            )
        ]
        for tech in self._fingerprint(headers):
            yields.append(
                Technology(id=f"tech:{tech}", props={"name": tech, "on": url, "source": "header"})
            )
        return [
            Fact(
                kind="alive",
                about=obs.entrypoint_id,
                data={"url": url, "status": raw.get("status")},
                yields=tuple(yields),
            )
        ]

    def _fingerprint(self, headers: dict) -> list[str]:
        """Read technology names straight off the response headers."""
        lower = {k.lower(): v for k, v in headers.items()}
        techs: list[str] = []
        for header in _TECH_HEADERS:
            value = lower.get(header.lower())
            if value:
                techs.append(value.strip())
        return techs

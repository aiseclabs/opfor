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

_RESOLVE_WORKERS = 100

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


def _http_get(url: str, body_cap: int = 0) -> dict:
    """One GET, returning a raw dict. Never raises, errors are data."""
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=_GET_TIMEOUT) as resp:
            body = resp.read(body_cap).decode("utf-8", "replace") if body_cap else ""
            return {"url": url, "status": resp.status, "headers": dict(resp.headers.items()), "body": body}
    except urllib.error.HTTPError as exc:
        body = exc.read(body_cap).decode("utf-8", "replace") if body_cap else ""
        headers = dict(exc.headers.items()) if exc.headers else {}
        return {"url": url, "status": exc.code, "headers": headers, "body": body}
    except urllib.error.URLError as exc:
        return {"url": url, "status": None, "error": str(exc.reason)}


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
        # Probe all unprobed live hosts in one concurrent batch.
        services = graph.entities("service")
        probed = {s.props.get("domain") for s in services}  # type: ignore[attr-defined]
        to_probe = sorted(n for n in live if n in known and n not in probed)
        if to_probe:
            eps.append(self._probe_batch_ep([(n, known[n]) for n in to_probe], len(services)))
        # Run every security check on every live service in one concurrent batch.
        checkable = [s for s in services if s.props.get("status") is not None]  # type: ignore[attr-defined]
        if checkable and self._checks:
            eps.append(self._check_batch_ep(checkable, len(checkable)))
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

    def _probe_batch_ep(self, pairs: list[tuple[str, str]], seq: int) -> Entrypoint:
        return Entrypoint(
            id=f"probe-batch::{seq}",
            target_id="(batch)",
            kind="http-batch",
            ref=f"{len(pairs)} hosts",
            actions=("probe_all",),
            props={
                "pairs": [list(p) for p in pairs],
                "scope_hosts": [name for name, _ in pairs],
                "action_tiers": {"probe_all": "probe"},
            },
        )

    def _check_batch_ep(self, services: list, seq: int) -> Entrypoint:
        items = []
        for svc in services:
            for check in self._checks:
                items.append(
                    {
                        "url": svc.id,
                        "domain": svc.props.get("domain"),
                        "path": check.get("path", "/"),
                        "check": check,
                    }
                )
        return Entrypoint(
            id=f"check-batch::{seq}",
            target_id="(batch)",
            kind="check-batch",
            ref=f"{len(items)} checks",
            actions=("check_all",),
            props={
                "items": items,
                "scope_hosts": [s.props.get("domain") for s in services],
                "action_tiers": {"check_all": "probe"},
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
        if action == "probe_all":
            return self._act_probe_all(entrypoint)
        if action == "check":
            return self._act_check(entrypoint)
        if action == "check_all":
            return self._act_check_all(entrypoint)
        raise ValueError(
            f"recon hand supports discover_roots, subdomains, resolve_all, "
            f"get, probe_all, check, check_all, got: {action}"
        )

    def _act_probe_all(self, entrypoint: Entrypoint) -> Observation:
        pairs = entrypoint.props["pairs"]

        def one(pair):
            name, url = pair
            return name, {**_http_get(url), "domain": name}

        with ThreadPoolExecutor(max_workers=_RESOLVE_WORKERS) as pool:
            results = dict(pool.map(one, pairs))
        return Observation(entrypoint_id=entrypoint.id, action="probe_all", raw={"results": results})

    def _act_check(self, entrypoint: Entrypoint) -> Observation:
        base = entrypoint.props["url"]
        path = entrypoint.props["path"]
        check = entrypoint.props["check"]
        domain = entrypoint.props["domain"]
        url = urllib.parse.urljoin(base, path.lstrip("/"))
        raw = {**_http_get(url, _BODY_CAP), "domain": domain, "check": check}
        return Observation(entrypoint_id=entrypoint.id, action="check", raw=raw)

    def _act_check_all(self, entrypoint: Entrypoint) -> Observation:
        items = entrypoint.props["items"]

        def one(item):
            url = urllib.parse.urljoin(item["url"], item["path"].lstrip("/"))
            return {**_http_get(url, _BODY_CAP), "domain": item["domain"], "check": item["check"]}

        with ThreadPoolExecutor(max_workers=_RESOLVE_WORKERS) as pool:
            results = list(pool.map(one, items))
        return Observation(entrypoint_id=entrypoint.id, action="check_all", raw={"results": results})

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
        if observation.action == "probe_all":
            return self._norm_probe_all(observation)
        if observation.action == "check":
            return self._norm_check(observation)
        if observation.action == "check_all":
            return self._norm_check_all(observation)
        return []

    def _check_finding(self, raw: dict) -> Finding | None:
        """Apply a check's data-defined matcher to one raw response."""
        check = raw.get("check", {})
        if raw.get("error"):
            return None
        match = check.get("match", {})
        if "status" in match and raw.get("status") != match["status"]:
            return None
        if "body_contains" in match:
            if str(match["body_contains"]).lower() not in (raw.get("body") or "").lower():
                return None
        if "header_missing" in match:
            present = {k.lower() for k in (raw.get("headers") or {})}
            if str(match["header_missing"]).lower() in present:
                return None
        cid = check.get("id", "check")
        return Finding(
            id=f"finding:{cid}:{raw.get('domain')}",
            props={
                "title": check.get("title", cid),
                "severity": check.get("severity", "info"),
                "domain": raw.get("domain"),
                "url": raw.get("url"),
                "evidence": f"{cid} matched at {raw.get('url')} (status {raw.get('status')})",
            },
        )

    def _norm_check(self, obs: Observation) -> list[Fact]:
        finding = self._check_finding(obs.raw)
        if finding is None:
            cid = obs.raw.get("check", {}).get("id", "check")
            return [Fact(kind="check-clean", about=obs.entrypoint_id, data={"id": cid})]
        return [Fact(kind="vuln", about=obs.entrypoint_id, data={"id": finding.props.get("title")}, yields=(finding,))]

    def _norm_check_all(self, obs: Observation) -> list[Fact]:
        findings = []
        for raw in obs.raw.get("results", []):
            f = self._check_finding(raw)
            if f is not None:
                findings.append(f)
        return [
            Fact(
                kind="checks-done",
                about=obs.entrypoint_id,
                data={"ran": len(obs.raw.get("results", [])), "findings": len(findings)},
                yields=tuple(findings),
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

    def _service_entities(self, raw: dict) -> list[object]:
        """A Service plus any fingerprinted Technologies from one probe response.

        A Service is recorded even on a request error, with status None, so the
        host is not probed again. Only services with a status are checkable.
        """
        url = raw.get("url")
        out: list[object] = [
            Service(id=url, props={"domain": raw.get("domain"), "status": raw.get("status")})
        ]
        for tech in self._fingerprint(raw.get("headers", {})):
            out.append(Technology(id=f"tech:{tech}", props={"name": tech, "on": url, "source": "header"}))
        return out

    def _norm_get(self, obs: Observation) -> list[Fact]:
        return [
            Fact(
                kind="alive",
                about=obs.entrypoint_id,
                data={"url": obs.raw.get("url"), "status": obs.raw.get("status")},
                yields=tuple(self._service_entities(obs.raw)),
            )
        ]

    def _norm_probe_all(self, obs: Observation) -> list[Fact]:
        results = obs.raw.get("results", {})
        entities: list[object] = []
        live = 0
        for raw in results.values():
            entities.extend(self._service_entities(raw))
            if raw.get("status") is not None:
                live += 1
        return [
            Fact(
                kind="probed-batch",
                about=obs.entrypoint_id,
                data={"probed": len(results), "responding": live},
                yields=tuple(entities),
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

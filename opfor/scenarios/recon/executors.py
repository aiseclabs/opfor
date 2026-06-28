"""Recon executors, one capability each.

These replace the old single ReconHand god-object. Each executor runs exactly one
tool against one target and structures the result, no batching (the control shell
runs independent tasks concurrently) and no attack decisions (the planner
decides). Network-dependent deps are injectable so executors are testable offline.
"""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from typing import Callable

from opfor.model import (
    Domain,
    Fact,
    Finding,
    Host,
    Observation,
    Service,
    Technology,
)
from opfor.plugins.base import Executor
from opfor.scenarios.recon.favicon import favicon_hash
from opfor.scenarios.recon.sources import (
    SUBDOMAIN_SOURCES,
    root_keyword,
    root_san_pivot,
)

_BODY_CAP = 2048
_GET_TIMEOUT = 8
_FAVICON_CAP = 200_000
_TECH_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator")


# --- shared helpers ---------------------------------------------------------


def _real_resolve(domain: str) -> list[str]:
    import socket

    infos = socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
    return sorted({ai[4][0] for ai in infos})


def http_get(url: str, body_cap: int = 0) -> dict:
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


def _fingerprint(headers: dict) -> list[str]:
    lower = {k.lower(): v for k, v in headers.items()}
    return [lower[h.lower()].strip() for h in _TECH_HEADERS if lower.get(h.lower())]


def _service_entities(raw: dict) -> list[object]:
    url = raw.get("url")
    out: list[object] = [Service(id=url, props={"domain": raw.get("domain"), "status": raw.get("status")})]
    for tech in _fingerprint(raw.get("headers", {})):
        out.append(Technology(id=f"tech:{tech}", props={"name": tech, "on": url, "source": "header"}))
    return out


def _check_finding(raw: dict) -> Finding | None:
    """Apply a check's data-defined matcher to one raw response."""
    check = raw.get("check", {})
    if raw.get("error"):
        return None
    match = check.get("match", {})
    body = (raw.get("body") or "").lower()
    headers_lower = {k.lower(): str(v).lower() for k, v in (raw.get("headers") or {}).items()}
    if "status" in match and raw.get("status") != match["status"]:
        return None
    if "body_contains" in match and str(match["body_contains"]).lower() not in body:
        return None
    if "body_not_contains" in match:
        blocked = match["body_not_contains"]
        blocked = [blocked] if isinstance(blocked, str) else blocked
        if any(str(b).lower() in body for b in blocked):
            return None
    if "content_type_excludes" in match:
        if str(match["content_type_excludes"]).lower() in headers_lower.get("content-type", ""):
            return None
    if "header_missing" in match and str(match["header_missing"]).lower() in headers_lower:
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
            "status": raw.get("status"),
            "content_type": headers_lower.get("content-type", ""),
            "body_snippet": (raw.get("body") or "")[:240],
        },
    )


def _candidate_facts(obs: Observation, source: str, confidence: str) -> list[Fact]:
    org = obs.raw["org"]
    cands = tuple(
        Domain(id=r, props={"candidate": True, "from": org, "source": source, "confidence": confidence})
        for r in obs.raw.get("roots", [])
    )
    return [
        Fact(kind="candidate-roots", about=obs.entrypoint_id, data={"from": org, "source": source, "count": len(cands)}, yields=cands)
    ]


# --- executors --------------------------------------------------------------


class RootKeywordExecutor(Executor):
    capability = "root_keyword"

    def __init__(self, search: Callable[[str], list[str]] = root_keyword) -> None:
        self._search = search

    def run(self, task, graph) -> Observation:
        org = task.target
        try:
            raw = {"org": org, "roots": self._search(org)}
        except Exception as exc:  # noqa: BLE001
            raw = {"org": org, "roots": [], "error": type(exc).__name__}
        return Observation(entrypoint_id=task.id, action="root_keyword", raw=raw)

    def perceive(self, observation) -> list[Fact]:
        return _candidate_facts(observation, "keyword", "low")


class RootPivotExecutor(Executor):
    capability = "root_pivot"

    def __init__(self, pivot: Callable[[str], list[str]] = root_san_pivot) -> None:
        self._pivot = pivot

    def run(self, task, graph) -> Observation:
        root = task.target
        try:
            raw = {"org": root, "roots": self._pivot(root)}
        except Exception as exc:  # noqa: BLE001
            raw = {"org": root, "roots": [], "error": type(exc).__name__}
        return Observation(entrypoint_id=task.id, action="root_pivot", raw=raw)

    def perceive(self, observation) -> list[Fact]:
        return _candidate_facts(observation, "cert-san", "medium")


class SubdomainExecutor(Executor):
    capability = "subdomains"

    def __init__(self, sources=None) -> None:
        self._sources = sources if sources is not None else SUBDOMAIN_SOURCES

    def run(self, task, graph) -> Observation:
        domain = task.target
        names: set[str] = set()
        report: dict[str, object] = {}
        for label, fetch in self._sources:
            try:
                got = fetch(domain)
                names.update(got)
                report[label] = len(got)
            except Exception as exc:  # noqa: BLE001
                report[label] = f"error:{type(exc).__name__}"
        return Observation(entrypoint_id=task.id, action="subdomains", raw={"domain": domain, "names": sorted(names), "sources": report})

    def perceive(self, observation) -> list[Fact]:
        raw = observation.raw
        root = raw["domain"]
        clean = {
            n.strip().lstrip("*.").lower()
            for n in raw.get("names", [])
            if n
        }
        clean = {n for n in clean if n == root or n.endswith("." + root)}
        return [
            Fact(
                kind="subdomains-found",
                about=observation.entrypoint_id,
                data={"root": root, "count": len(clean), "sources": raw.get("sources", {})},
                yields=tuple(Domain(id=n, props={"parent": root, "depth": n.count(".")}) for n in sorted(clean)),
            )
        ]


class DnsExecutor(Executor):
    capability = "dns_resolve"

    def __init__(self, resolve_fn: Callable[[str], list[str]] = _real_resolve) -> None:
        self._resolve = resolve_fn

    def run(self, task, graph) -> Observation:
        domain = task.target
        try:
            ips = list(self._resolve(domain))
        except OSError:
            ips = []
        return Observation(entrypoint_id=task.id, action="dns_resolve", raw={"domain": domain, "ips": ips})

    def perceive(self, observation) -> list[Fact]:
        d = observation.raw["domain"]
        ips = observation.raw.get("ips") or []
        host = Host(id=f"host:{d}", props={"domain": d, "ips": ips, "live": bool(ips)})
        return [Fact(kind="resolved", about=observation.entrypoint_id, data={"domain": d, "live": bool(ips)}, yields=(host,))]


class HttpProbeExecutor(Executor):
    capability = "http_probe"

    def run(self, task, graph) -> Observation:
        raw = {**http_get(task.params["url"]), "domain": task.target}
        return Observation(entrypoint_id=task.id, action="http_probe", raw=raw)

    def perceive(self, observation) -> list[Fact]:
        raw = observation.raw
        return [Fact(kind="alive", about=observation.entrypoint_id, data={"url": raw.get("url"), "status": raw.get("status")}, yields=tuple(_service_entities(raw)))]


class HttpCheckExecutor(Executor):
    capability = "http_check"

    def run(self, task, graph) -> Observation:
        url = urllib.parse.urljoin(task.params["url"], task.params["path"].lstrip("/"))
        raw = {**http_get(url, _BODY_CAP), "domain": task.target, "check": task.params["check"]}
        return Observation(entrypoint_id=task.id, action="http_check", raw=raw)

    def perceive(self, observation) -> list[Fact]:
        finding = _check_finding(observation.raw)
        if finding is None:
            cid = observation.raw.get("check", {}).get("id", "check")
            return [Fact(kind="check-clean", about=observation.entrypoint_id, data={"id": cid})]
        return [Fact(kind="vuln", about=observation.entrypoint_id, data={"id": finding.props.get("title")}, yields=(finding,))]


class FaviconExecutor(Executor):
    capability = "favicon"

    def run(self, task, graph) -> Observation:
        url = urllib.parse.urljoin(task.params["url"], "favicon.ico")
        domain = task.target
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=_GET_TIMEOUT) as resp:
                content = resp.read(_FAVICON_CAP)
                h = favicon_hash(content) if content and resp.status == 200 else None
                raw = {"domain": domain, "url": url, "hash": h}
        except Exception as exc:  # noqa: BLE001
            raw = {"domain": domain, "url": url, "hash": None, "error": type(exc).__name__}
        return Observation(entrypoint_id=task.id, action="favicon", raw=raw)

    def perceive(self, observation) -> list[Fact]:
        raw = observation.raw
        if raw.get("hash") is not None:
            return [Fact(kind="favicon", about=raw["domain"], data={"domain": raw["domain"], "url": raw["url"], "hash": raw["hash"]})]
        return [Fact(kind="favicon-none", about=observation.entrypoint_id, data={})]


def default_executors(checks=None) -> dict[str, Executor]:
    return {
        "root_keyword": RootKeywordExecutor(),
        "root_pivot": RootPivotExecutor(),
        "subdomains": SubdomainExecutor(),
        "dns_resolve": DnsExecutor(),
        "http_probe": HttpProbeExecutor(),
        "http_check": HttpCheckExecutor(),
        "favicon": FaviconExecutor(),
    }

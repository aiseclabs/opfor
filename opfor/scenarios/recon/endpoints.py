"""Endpoint discovery, the interface fanout, self-built and multi-source.

Given a live service, enumerate which endpoints it exposes. Mirrors the
subdomain multi-source pattern: each source is one executor that returns
Endpoint entities, the graph dedupes them, and the scope tier ladder enforces
the passive-before-active ordering (openapi/archive are passive recon, js is
probe, brute is intrusive). No external binary, just HTTP clients we write.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from typing import Callable

from opfor.agent.planner import Planner
from opfor.engine.graph import SituationGraph
from opfor.engine.tasks import Task
from opfor.model import Endpoint, Fact, Observation
from opfor.plugins.base import Executor
from opfor.scenarios.recon.executors import http_get

_HTTP_VERBS = {"get", "post", "put", "delete", "patch", "options", "head"}
_SPEC_PATHS = [
    "/swagger.json", "/openapi.json", "/swagger-json", "/api-docs",
    "/v3/api-docs", "/v2/api-docs", "/api/swagger.json", "/api/openapi.json",
]
# API-shaped paths inside JavaScript bundles.
_JS_PATH = re.compile(r"""['"`](/(?:api|rest|graphql|v\d+|internal|private|admin)[\w./\-]*)['"`]""")
_SCRIPT_SRC = re.compile(r"""<script[^>]+src=['"]([^'"]+\.js[^'"]*)['"]""", re.IGNORECASE)
_MAX_JS = 8


def _endpoint(host: str, method: str, path: str, source: str, confidence: str, params=None, base=None) -> Endpoint:
    # Scheme follows the service the endpoint was found on (an http-only host must
    # not get https endpoint urls), defaulting to https for host-only sources.
    scheme = urllib.parse.urlsplit(base).scheme if base else "https"
    return Endpoint(
        id=f"{method.upper()} {path}",
        props={
            "host": host, "method": method.upper(), "path": path,
            "params": params or [], "source": source, "confidence": confidence,
            "url": f"{scheme or 'https'}://{host}{path}",
        },
    )


# --- OpenAPI / Swagger ------------------------------------------------------


class OpenApiExecutor(Executor):
    capability = "openapi_parse"

    def __init__(self, spec_paths=None) -> None:
        self._spec_paths = spec_paths or _SPEC_PATHS

    def run(self, task, graph) -> Observation:
        base = task.params["base_url"].rstrip("/")
        host = task.params["host"]
        for sp in self._spec_paths:
            raw = http_get(base + sp, body_cap=400_000)
            if raw.get("status") != 200 or not raw.get("body"):
                continue
            try:
                spec = json.loads(raw["body"])
            except Exception:
                continue
            if isinstance(spec, dict) and "paths" in spec:
                return Observation(entrypoint_id=task.id, action="openapi_parse",
                                   raw={"host": host, "base": base, "spec_url": base + sp, "spec": spec["paths"]})
        return Observation(entrypoint_id=task.id, action="openapi_parse", raw={"host": host, "base": base, "spec": None})

    def perceive(self, observation) -> list[Fact]:
        raw = observation.raw
        host = raw["host"]
        spec = raw.get("spec")
        if not spec:
            return [Fact(kind="no-openapi", about=observation.entrypoint_id, data={"host": host})]
        endpoints = []
        for path, methods in spec.items():
            if not isinstance(methods, dict):
                continue
            for method, info in methods.items():
                if method.lower() not in _HTTP_VERBS:
                    continue
                params = [p.get("name") for p in (info.get("parameters") or []) if isinstance(p, dict)]
                endpoints.append(_endpoint(host, method, path, "openapi", "high", params, base=raw.get("base")))
        return [Fact(kind="endpoints-found", about=observation.entrypoint_id,
                     data={"host": host, "source": "openapi", "count": len(endpoints), "spec_url": raw.get("spec_url")},
                     yields=tuple(endpoints))]


# --- JavaScript bundles -----------------------------------------------------


class JsEndpointsExecutor(Executor):
    capability = "js_endpoints"

    def run(self, task, graph) -> Observation:
        base = task.params["base_url"].rstrip("/")
        host = task.params["host"]
        root = http_get(base + "/", body_cap=200_000)
        paths: set[str] = set(_JS_PATH.findall(root.get("body") or ""))
        js_srcs = _SCRIPT_SRC.findall(root.get("body") or "")[:_MAX_JS]
        for src in js_srcs:
            url = urllib.parse.urljoin(base + "/", src)
            if urllib.parse.urlsplit(url).netloc != urllib.parse.urlsplit(base).netloc:
                continue
            js = http_get(url, body_cap=400_000)
            paths.update(_JS_PATH.findall(js.get("body") or ""))
        return Observation(entrypoint_id=task.id, action="js_endpoints",
                           raw={"host": host, "base": base, "paths": sorted(paths), "js_count": len(js_srcs)})

    def perceive(self, observation) -> list[Fact]:
        raw = observation.raw
        host = raw["host"]
        eps = tuple(_endpoint(host, "GET", p, "js", "medium", base=raw.get("base")) for p in raw.get("paths", []))
        return [Fact(kind="endpoints-found", about=observation.entrypoint_id,
                     data={"host": host, "source": "js", "count": len(eps)}, yields=eps)]


# --- Archive / passive URL sources -----------------------------------------


def _wayback(host: str) -> list[str]:
    url = f"http://web.archive.org/cdx/search/cdx?url={urllib.parse.quote(host)}/*&output=json&fl=original&collapse=urlkey&limit=2000"
    rows = json.loads(http_get(url, body_cap=2_000_000).get("body") or "[]")
    return [r[0] for r in rows[1:] if r]  # row 0 is the header


def _urlscan(host: str) -> list[str]:
    url = f"https://urlscan.io/api/v1/search/?q=domain:{urllib.parse.quote(host)}&size=100"
    data = json.loads(http_get(url, body_cap=2_000_000).get("body") or "{}")
    out = []
    for r in data.get("results", []):
        for key in ("page", "task"):
            u = (r.get(key) or {}).get("url")
            if u:
                out.append(u)
    return out


_ARCHIVE_SOURCES = [("wayback", _wayback), ("urlscan", _urlscan)]


class ArchiveExecutor(Executor):
    capability = "archive_urls"

    def __init__(self, sources=None) -> None:
        self._sources = sources if sources is not None else _ARCHIVE_SOURCES

    def run(self, task, graph) -> Observation:
        host = task.params["host"]
        urls: set[str] = set()
        report: dict[str, object] = {}
        for label, fetch in self._sources:
            try:
                got = fetch(host)
                urls.update(got)
                report[label] = len(got)
            except Exception as exc:  # noqa: BLE001
                report[label] = f"error:{type(exc).__name__}"
        return Observation(entrypoint_id=task.id, action="archive_urls",
                           raw={"host": host, "urls": sorted(urls), "sources": report})

    def perceive(self, observation) -> list[Fact]:
        host = observation.raw["host"]
        paths: set[str] = set()
        for u in observation.raw.get("urls", []):
            split = urllib.parse.urlsplit(u)
            if split.netloc and host not in split.netloc:
                continue
            paths.add(split.path or "/")
        eps = tuple(_endpoint(host, "GET", p, "archive", "low") for p in sorted(paths))
        return [Fact(kind="endpoints-found", about=observation.entrypoint_id,
                     data={"host": host, "source": "archive", "count": len(eps), "sources": observation.raw.get("sources", {})},
                     yields=eps)]


# --- planner ----------------------------------------------------------------


class EndpointPlanner(Planner):
    """For each live service, run the passive endpoint sources, then the active."""

    def expand(self, graph: SituationGraph) -> list[Task]:
        tasks: list[Task] = []
        for svc in graph.entities("service"):
            if svc.props.get("status") is None:
                continue
            host = svc.props.get("domain")
            base = svc.id
            tasks.append(Task(id=f"openapi:{host}", capability="openapi_parse", target=host,
                              params={"base_url": base, "host": host}, tier="recon", osint=True, scope_host=host))
            tasks.append(Task(id=f"archive:{host}", capability="archive_urls", target=host,
                              params={"host": host}, tier="recon", osint=True, scope_host=host))
            tasks.append(Task(id=f"js:{host}", capability="js_endpoints", target=host,
                              params={"base_url": base, "host": host}, tier="probe", scope_host=host))
        return tasks


def endpoint_executors() -> dict[str, Executor]:
    return {
        "openapi_parse": OpenApiExecutor(),
        "archive_urls": ArchiveExecutor(),
        "js_endpoints": JsEndpointsExecutor(),
    }

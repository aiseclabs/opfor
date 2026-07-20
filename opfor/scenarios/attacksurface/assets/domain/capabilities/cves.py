"""ENRICH-phase CVE lookup capability, identify a product and query a public database."""

from __future__ import annotations

import json
from urllib.parse import urlparse

from opfor.core import Capability, Done, Fact, Outcome, Phase, Task, World
from opfor.scenarios.attacksurface.assets.domain.sources import info_from_openapi
from opfor.scenarios.attacksurface.assets.domain.types import CVE, CVEScan
from opfor.scenarios.attacksurface.assets.domain.capabilities.helpers import net_failed


class CVELookup(Capability):
    """ENRICH: identify a live host's product and look up its known vulnerabilities.

    The identify seam names the product, version, and CPE from the host's gathered
    evidence, and the CVE seam looks that version up in a public database. Both are
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
            return net_failed("product identification", exc)
        product = str(found.get("product", "")).strip()
        version = str(found.get("version", "")).strip()
        cpe = str(found.get("cpe", "")).strip()
        cves: tuple[CVE, ...] = ()
        match = ""
        if product:
            try:
                raw = self._cve(product, version, cpe)
            except Exception as exc:
                return net_failed("cve lookup", exc)
            # The whole list is found on one basis per lookup, so the scan records it once.
            match = str(raw[0].get("match", "")) if raw else ""
            cves = tuple(
                CVE(id=str(c.get("id", "")), cvss=c.get("cvss"),
                    severity=str(c.get("severity", "")), summary=str(c.get("summary", "")),
                    references=tuple(str(u) for u in c.get("references", ())))
                for c in raw if c.get("id"))
        payload = CVEScan(product=product, version=version, cpe=cpe, match=match, cves=cves)
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

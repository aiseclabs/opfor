"""Deterministic host classification helpers: the shared source functions the report and the
profiling capability both use, so framework and edge detection has one implementation.
"""

from __future__ import annotations

import re

from opfor.scenarios.attacksurface.assets.domain.sources.profile import (
    classify_frameworks,
    classify_edge,
    is_ip,
)
from opfor.scenarios.attacksurface.assets.domain.types import HTTP, Resolved

_FRAMEWORKS = {
    "Next.js": {"body": ['id="__next"'], "headers": ["x-powered-by: next.js"], "version": None},
    "Angular": {"body": ["ng-version="], "headers": [],
                "version": re.compile(r'ng-version="([0-9]+\.[0-9]+\.[0-9]+)"', re.IGNORECASE)},
}
_FRONTING = {
    "cdn": {"cnames": ["cloudflare.net"], "servers": ["cloudflare"], "headers": ["cf-ray"]},
    "vendor": {"cnames": ["github.io"], "servers": [], "headers": []},
}


def _http(*, server="", headers=(), body=""):
    return HTTP(alive=True, status=200, url="https://h/", server=server, title="",
                body=body.lower(), location="", headers=tuple(headers))


def test_classify_frameworks_reads_body_and_header_and_version():
    assert classify_frameworks(_http(body='<div id="__next">'), _FRAMEWORKS) == ["Next.js"]
    assert classify_frameworks(_http(headers=(("X-Powered-By", "Next.js"),)), _FRAMEWORKS) == ["Next.js"]
    assert classify_frameworks(_http(body='<app ng-version="16.2.0">'), _FRAMEWORKS) == ["Angular 16.2.0"]


def test_classify_frameworks_is_empty_for_no_response_or_no_match():
    assert classify_frameworks(None, _FRAMEWORKS) == []
    assert classify_frameworks(_http(server="nginx", body="<html>hi</html>"), _FRAMEWORKS) == []


def test_classify_edge_prefers_cname_then_marker_then_bare_ip():
    resolved = Resolved(resolvable=True, addresses=("1.2.3.4",), cnames=("x.cloudflare.net",))
    assert classify_edge("www.h", resolved, _http(), _FRONTING) == ("cdn", "CNAME to cloudflare.net")
    assert classify_edge("api.h", None, _http(headers=(("cf-ray", "1"),)), _FRONTING)[0] == "cdn"
    assert classify_edge("203.0.113.5", None, _http(), _FRONTING)[0] == "direct"


def test_classify_edge_leaves_an_unrecognized_named_host_untagged():
    assert classify_edge("app.h", None, _http(server="nginx"), _FRONTING) is None


def test_is_ip():
    assert is_ip("203.0.113.5") and is_ip("2606:4700::1")
    assert not is_ip("example.com")


def test_profile_host_records_product_frameworks_and_edge_in_one_fact():
    from opfor.core import Fact, Node, Task, World
    from opfor.scenarios.attacksurface.assets.domain.capabilities import ProfileHost
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData, Resolved

    world = World()
    world.add(Node(id="domain:h", type="domain",
                   payload=DomainData(name="h", root="h", source="hint")))
    world.absorb([Fact(kind="resolved", about="domain:h",
                       payload=Resolved(resolvable=True, addresses=("1.2.3.4",)))])
    world.absorb([Fact(kind="http", about="domain:h", payload=_http(server="grafana"))])

    identify = lambda evidence: {"product": "Grafana", "version": "9.3.2", "cpe": "grafana:grafana"}
    out = ProfileHost(identify, lambda http: ["Next.js"], lambda n, r, h: ("cdn", "CNAME x")).run(
        Task(capability="domain_profile", node="domain:h"), world)
    profile = out.facts[0].payload
    assert out.facts[0].kind == "host_profile"
    assert profile.product == "Grafana" and profile.version == "9.3.2"
    assert profile.frameworks == ("Next.js",)
    assert profile.edge == "cdn"


def test_report_renders_product_tech_and_edge_from_the_host_profile_fact():
    from opfor.core import Fact, Node, World
    from opfor.scenarios.attacksurface.render import SurfaceRenderer
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData, HostProfile, Resolved

    world = World()
    world.add(Node(id="domain:h", type="domain", payload=DomainData(name="h", root="h", source="passive")))
    world.absorb([Fact(kind="resolved", about="domain:h",
                       payload=Resolved(resolvable=True, addresses=("1.2.3.4",)))])
    world.absorb([Fact(kind="http", about="domain:h", payload=_http(server="nginx"))])
    world.absorb([Fact(kind="host_profile", about="domain:h", payload=HostProfile(
        product="Grafana", version="9.3.2", frameworks=("Next.js",),
        edge="cdn", edge_evidence="CNAME to cloudflare.net"))])
    report = "\n".join(SurfaceRenderer([], []).units(world))
    assert "edge cdn, CNAME to cloudflare.net" in report
    assert "tech: Next.js" in report
    assert "product: Grafana 9.3.2" in report


def test_cve_lookup_reads_identity_from_the_host_profile_fact():
    # identity is derived by profiling and read here, so a CVE outage never discards it
    from opfor.core import Fact, Node, Task, World
    from opfor.scenarios.attacksurface.assets.domain.capabilities import CVELookup
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData, HostProfile

    world = World()
    world.add(Node(id="domain:h", type="domain", payload=DomainData(name="h", root="h", source="hint")))
    world.absorb([Fact(kind="host_profile", about="domain:h",
                       payload=HostProfile(product="Grafana", version="9.3.2", cpe="grafana:grafana"))])

    def cves(product, version, cpe=""):
        assert (product, version, cpe) == ("Grafana", "9.3.2", "grafana:grafana")
        return [{"id": "CVE-2021-1", "match": "version"}]

    out = CVELookup(cves).run(Task(capability="cve_scan", node="domain:h"), world)
    scan = out.facts[0].payload
    assert scan.product == "Grafana" and scan.match == "version"
    assert scan.cves[0].id == "CVE-2021-1"

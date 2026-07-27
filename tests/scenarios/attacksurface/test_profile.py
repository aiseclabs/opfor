"""Deterministic host classification helpers: the shared source functions the report and the
profiling capability both use, so framework detection has one implementation.
"""

from __future__ import annotations

import re

from opfor.scenarios.attacksurface.assets.domain.classifiers import classify_frameworks
from opfor.scenarios.attacksurface.assets.domain.types import HTTPProbe

_FRAMEWORKS = {
    "Next.js": {"body": ['id="__next"'], "headers": ["x-powered-by: next.js"], "version": None},
    "Angular": {"body": ["ng-version="], "headers": [],
                "version": re.compile(r'ng-version="([0-9]+\.[0-9]+\.[0-9]+)"', re.IGNORECASE)},
}


def _http(*, server="", headers=(), body=""):
    return HTTPProbe(alive=True, status=200, url="https://h/", server=server, title="",
                body=body.lower(), location="", headers=tuple(headers))


def test_classify_frameworks_reads_body_and_header_and_version():
    assert classify_frameworks(_http(body='<div id="__next">'), _FRAMEWORKS) == ["Next.js"]
    assert classify_frameworks(_http(headers=(("X-Powered-By", "Next.js"),)), _FRAMEWORKS) == ["Next.js"]
    assert classify_frameworks(_http(body='<app ng-version="16.2.0">'), _FRAMEWORKS) == ["Angular 16.2.0"]


def test_classify_frameworks_is_empty_for_no_response_or_no_match():
    assert classify_frameworks(None, _FRAMEWORKS) == []
    assert classify_frameworks(_http(server="nginx", body="<html>hi</html>"), _FRAMEWORKS) == []


def test_profile_host_records_product_and_frameworks_in_one_fact():
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
    out = ProfileHost(identify, lambda http: ["Next.js"]).run(
        Task(capability="domain_profile", node="domain:h"), world)
    profile = out.facts[0].payload
    assert out.facts[0].kind == "host_profile"
    assert profile.product == "Grafana" and profile.version == "9.3.2"
    assert profile.frameworks == ("Next.js",)


def test_profile_host_records_a_coverage_gap_when_the_seam_finds_the_evidence_too_thin():
    # a live host the identify seam could not judge for lack of evidence is a visible blind spot,
    # its empty product is unknown rather than a confirmed bespoke negative, invariant 3 and 5
    from opfor.core import Fact, Node, Task, World
    from opfor.scenarios.attacksurface.assets.domain.capabilities import ProfileHost
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData

    world = World()
    world.add(Node(id="domain:h", type="domain",
                   payload=DomainData(name="h", root="h", source="passive")))
    world.absorb([Fact(kind="http", about="domain:h", payload=_http(body="hi"))])

    identify = lambda evidence: {"product": "", "version": "", "cpe": "", "conclusive": False}
    out = ProfileHost(identify, lambda http: []).run(
        Task(capability="domain_profile", node="domain:h"), world)
    kinds = [f.kind for f in out.facts]
    assert "host_profile" in kinds and "coverage_gap" in kinds
    gap = next(f.payload for f in out.facts if f.kind == "coverage_gap")
    assert gap.scan == "domain_profile" and gap.host == "h"


def test_profile_host_records_no_gap_when_an_empty_product_is_a_conclusive_negative():
    # the seam judged the evidence sufficient and named no product, a real bespoke negative, so
    # there is no blind spot to record, only the host_profile fact
    from opfor.core import Fact, Node, Task, World
    from opfor.scenarios.attacksurface.assets.domain.capabilities import ProfileHost
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData

    world = World()
    world.add(Node(id="domain:h", type="domain",
                   payload=DomainData(name="h", root="h", source="passive")))
    world.absorb([Fact(kind="http", about="domain:h", payload=_http(body="a bespoke app"))])

    identify = lambda evidence: {"product": "", "version": "", "cpe": "", "conclusive": True}
    out = ProfileHost(identify, lambda http: []).run(
        Task(capability="domain_profile", node="domain:h"), world)
    assert [f.kind for f in out.facts] == ["host_profile"]


def test_report_renders_product_and_tech_from_the_host_profile_fact():
    from opfor.core import Fact, Node, World
    from opfor.scenarios.attacksurface.render import SurfaceRenderer
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData, HostProfile, Resolved

    world = World()
    world.add(Node(id="domain:h", type="domain", payload=DomainData(name="h", root="h", source="passive")))
    world.absorb([Fact(kind="resolved", about="domain:h",
                       payload=Resolved(resolvable=True, addresses=("1.2.3.4",)))])
    world.absorb([Fact(kind="http", about="domain:h", payload=_http(server="nginx"))])
    world.absorb([Fact(kind="host_profile", about="domain:h", payload=HostProfile(
        product="Grafana", version="9.3.2", frameworks=("Next.js",)))])
    report = "\n".join(SurfaceRenderer([], []).units(world))
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

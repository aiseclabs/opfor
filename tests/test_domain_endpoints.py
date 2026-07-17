from __future__ import annotations

from opfor.core import Node, World

from tests.surface_fixtures import *


def test_endpoints_enumerated_and_auth_classified():
    world = _seed()
    _run(world)
    eps = {n.id: n.payload for n in world.nodes("endpoint")}
    assert "endpoint:admin.example.com/.git/config" in eps
    assert eps["endpoint:admin.example.com/metrics"].auth_required is True
    assert eps["endpoint:admin.example.com/.env"].auth_required is False

def test_probe_list_includes_product_identity_and_version_paths():
    from opfor.scenarios.attacksurface.assets import domain as domain_class
    from opfor.scenarios.attacksurface.assets.domain import planner

    # the product identity and version endpoints are data in paths.yaml, probed by the
    # existing endpoint capability, so a later step can read the version for a cve match
    probe_paths = planner.load_plan_config(domain_class.KNOWLEDGE).probe_paths
    for path in ("/actuator/info", "/version", "/.well-known/openid-configuration", "/nacos/"):
        assert path in probe_paths

def test_batch_one_exposure_coverage_is_loaded():
    from opfor.scenarios.attacksurface.assets import domain as domain_class
    from opfor.scenarios.attacksurface.assets.domain import planner
    from opfor.scenarios.attacksurface.lifecycle.triage import _load_classes, _load_clues

    # new fixed-path leaks are probed, pure data in paths.yaml, no code
    probe_paths = planner.load_plan_config(domain_class.KNOWLEDGE).probe_paths
    for path in ("/.ssh/id_rsa", "/web.config", "/backup.sql", "/.git/index", "/.npmrc"):
        assert path in probe_paths

    knowledge = domain_class.KNOWLEDGE
    # new deterministic clues direct the model at the buried signals
    clue_ids = {c["id"] for c in _load_clues(knowledge / "exposures.yaml")}
    assert {"exposed-private-key", "exposed-htpasswd", "exposed-sql-dump"} <= clue_ids
    # new judgment families the model can reach for
    class_ids = {c["id"] for c in _load_classes(knowledge / "classes")}
    assert {"cors-misconfiguration", "verbose-error-disclosure"} <= class_ids

def test_static_assets_are_never_probed_into_endpoints():
    # admin's script names /main.css, a static asset, so it must not become an endpoint
    world = _seed()
    _run(world)
    assert world.node("endpoint:admin.example.com/main.css") is None

def test_soft_200_host_yields_only_its_real_interface():
    # spa answers 200 for every path, so the catch-all filter must keep only the real spec
    world = _seed()
    _run(world)
    spa = sorted(n.id for n in world.nodes("endpoint") if "spa.example.com" in n.id)
    assert spa == ["endpoint:spa.example.com/openapi.json"]

def test_html_posing_as_swagger_is_not_an_endpoint():
    world = _seed()
    _run(world)
    assert world.node("endpoint:spa.example.com/swagger.json") is None

def test_endpoint_probe_records_a_coverage_gap_when_a_path_errors():
    # one candidate path errors on the probe. The scan still returns the endpoints it
    # reached, but the dropped path is recorded as a coverage gap and surfaced as an INFO
    # finding, so a partial probe is never read as a clean, complete negative, invariant 5.
    def fetch(name, addresses, path):
        if name == "admin.example.com" and path == "/.git/config":
            raise TimeoutError("probe timed out")
        return _fetch(name, addresses, path)

    report, _scenario, world = _run_capturing(fetch_fn=fetch)
    gaps = [f.payload for f in world.facts("coverage_gap") if f.payload.scan == "domain_endpoints"]
    assert any(g.host == "admin.example.com" and g.failed >= 1 for g in gaps), \
        "a probe error must record a coverage_gap fact rather than be silently dropped"
    gap_findings = [f for f in report.findings if f.data.get("kind") == "coverage_gap"]
    assert any(f.severity == "INFO" and "admin.example.com" in f.where for f in gap_findings), \
        "the coverage gap must surface as an INFO finding, so a partial scan reads as partial"
    assert "TimeoutError" in "".join(f.evidence for f in gap_findings)

def test_endpoint_probe_records_a_coverage_gap_on_a_transport_failure_not_only_a_raise():
    # the real fetch seam swallows a connection error and returns status None rather than
    # raising, so the gap must be recorded from a None status too, else a WAF-blocked or
    # timed-out probe reads as a clean negative, invariant 5
    def fetch(name, addresses, path):
        if name == "admin.example.com" and path == "/.git/config":
            return {"status": None, "url": f"https://{name}{path}", "content_type": "",
                    "server": "", "title": "", "body": ""}
        return _fetch(name, addresses, path)

    _report, _scenario, world = _run_capturing(fetch_fn=fetch)
    gaps = [f.payload for f in world.facts("coverage_gap") if f.payload.scan == "domain_endpoints"]
    assert any(g.host == "admin.example.com" and any("no response" in r for r in g.reasons)
               for g in gaps), "a transport failure must record a coverage_gap, not vanish"

def test_endpoint_probe_reports_truncation_when_the_candidate_cap_is_hit():
    from opfor.core import Done, Task
    from opfor.scenarios.attacksurface.assets.domain.capabilities.http import Endpoints
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData

    world = World()
    world.add(Node(id="domain:h", type="domain", payload=DomainData(name="h", root="h", source="s")))
    paths = [f"/p{i}" for i in range(500)]

    def fetch(name, addresses, path):
        return {"status": 404, "url": f"https://{name}{path}", "content_type": "",
                "server": "", "title": "", "body": "", "location": ""}

    outcome = Endpoints(fetch).run(
        Task(capability="domain_endpoints", node="domain:h", params={"paths": paths}), world)
    assert isinstance(outcome, Done)
    gaps = [f.payload for f in outcome.facts if f.kind == "coverage_gap"]
    # the 400-candidate cap is surfaced, not a silent bound read as the whole surface
    assert gaps and any("cap" in r for r in gaps[0].reasons)

def test_endpoint_probe_flags_when_the_baseline_cannot_be_established():
    from opfor.core import Done, Task
    from opfor.scenarios.attacksurface.assets.domain.capabilities.http import Endpoints
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData

    world = World()
    world.add(Node(id="domain:h", type="domain", payload=DomainData(name="h", root="h", source="s")))

    def fetch(name, addresses, path):
        # only the real path answers, the baseline catch-all probes get no response
        if path == "/real":
            return {"status": 200, "url": f"https://{name}{path}", "content_type": "text/html",
                    "server": "", "title": "", "body": "x", "location": ""}
        return {"status": None, "url": f"https://{name}{path}", "content_type": "",
                "server": "", "title": "", "body": "", "location": ""}

    outcome = Endpoints(fetch).run(
        Task(capability="domain_endpoints", node="domain:h", params={"paths": ["/real"]}), world)
    assert isinstance(outcome, Done)
    gaps = [f.payload for f in outcome.facts if f.kind == "coverage_gap"]
    # a baseline that could not be established is flagged, so an unfiltered surface is loud
    assert gaps and any("baseline" in r for r in gaps[0].reasons)

def test_distinct_treats_a_differing_redirect_location_as_a_real_endpoint():
    from opfor.scenarios.attacksurface.assets.domain.capabilities.helpers import _distinct
    # a host that answers a blanket 302 to /login for unknown paths still hides a real /admin
    # that redirects to its own dashboard, so a differing location is distinct
    baseline = {"status": 302, "location": "https://h/login", "content_type": "", "body": ""}
    same = {"status": 302, "location": "https://h/login"}
    other = {"status": 302, "location": "https://h/admin/dashboard"}
    assert _distinct(same, baseline) is False
    assert _distinct(other, baseline) is True

def test_distinct_ignores_a_path_echoing_login_redirect_query():
    from opfor.scenarios.attacksurface.assets.domain.capabilities.helpers import _distinct
    # a login wall that echoes the requested path in ?next= gives every path a different raw
    # location, but it is one catch-all, so not distinct
    baseline = {"status": 302, "location": "https://h/login?next=/x", "content_type": "", "body": ""}
    echoed = {"status": 302, "location": "https://h/login?next=/admin"}
    assert _distinct(echoed, baseline) is False
    # a real redirect to a genuinely different path is still distinct
    assert _distinct({"status": 302, "location": "https://h/admin/dashboard"}, baseline) is True

def test_norm_url_keeps_the_query_so_a_query_bearing_poc_does_not_false_match():
    from opfor.scenarios.attacksurface.lifecycle.grounding import _norm_url
    # a PoC that names a query parameter must not normalize onto the query-less observed GET,
    # which would ground the finding in a materially different request
    assert _norm_url("https://h/api/data?debug=1") != _norm_url("https://h/api/data")
    # the query is order-normalized so cosmetic reordering still matches
    assert _norm_url("https://h/a?x=1&y=2") == _norm_url("https://h/a?y=2&x=1")

def test_a_resolvable_but_unreachable_seed_host_reports_a_gap_not_a_bare_clean():
    # a host resolves to a public address but times out on every probe, the ALB-behind-a-
    # firewall case. The run must not close clean with no notes, it must surface the reach it
    # could not achieve as a coverage gap, invariant 3 and 5.
    def probe(name, addresses=()):
        if name == ROOT:
            return {"alive": False, "status": None, "reason": "unreachable"}
        return _probe(name, addresses)

    report, _scenario, _world = _run_capturing(probe_fn=probe)
    gap_findings = [f for f in report.findings
                    if f.data.get("kind") == "coverage_gap" and f.data.get("scan") == "domain_http"]
    assert any(ROOT in f.where for f in gap_findings), (
        "a resolvable host the run could not reach must surface a domain_http coverage gap, "
        "never a bare closed-with-no-notes clean result")

def test_http_domain_records_a_gap_when_unreachable_but_not_when_refused():
    # a resolvable host that answers no connection reads as alive=False, the same shape a
    # host that genuinely serves no web content gives. A uniform timeout is a coverage gap,
    # the run could not reach the host, while a refused connection is a real negative, so the
    # gap is recorded for the first and not the second, invariant 3 and 5.
    from opfor.core import Done, Fact, Task
    from opfor.scenarios.attacksurface.assets.domain.capabilities.http import HTTPDomain
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData, Resolved

    world = World()
    world.add(Node(id="domain:h", type="domain", payload=DomainData(name="h", root="h", source="s")))
    world.absorb([Fact(kind="resolved", about="domain:h",
                       payload=Resolved(resolvable=True, addresses=("8.8.8.8",)))])
    task = Task(capability="domain_http", node="domain:h")

    unreachable = HTTPDomain(
        lambda name, addresses: {"alive": False, "status": None, "reason": "unreachable"}).run(task, world)
    assert isinstance(unreachable, Done)
    gaps = [f.payload for f in unreachable.facts if f.kind == "coverage_gap"]
    assert len(gaps) == 1 and gaps[0].scan == "domain_http" and gaps[0].host == "h"

    refused = HTTPDomain(
        lambda name, addresses: {"alive": False, "status": None, "reason": "refused"}).run(task, world)
    assert isinstance(refused, Done)
    assert not any(f.kind == "coverage_gap" for f in refused.facts)

def test_resolve_error_records_an_errored_fact_and_a_gap_not_a_bare_failed():
    from opfor.core import Done, Task
    from opfor.scenarios.attacksurface.assets.domain.capabilities.dns import ResolveDomain
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData

    world = World()
    world.add(Node(id="domain:h", type="domain", payload=DomainData(name="h", root="h", source="s")))

    def boom(name):
        raise RuntimeError("all DoH resolvers failed")

    out = ResolveDomain(boom).run(Task(capability="domain_resolve", node="domain:h"), world)
    # a resolver outage still records a resolved fact, so an org-level barrier is not wedged,
    # and a coverage gap keeps the failure loud rather than a bare Failed that leaves no trace
    assert isinstance(out, Done)
    resolved = [f.payload for f in out.facts if f.kind == "resolved"]
    assert resolved and resolved[0].errored is True and resolved[0].resolvable is False
    assert any(f.kind == "coverage_gap" for f in out.facts)

def test_harvest_crash_still_records_harvested_and_a_gap(monkeypatch):
    from opfor.core import Done, Fact, Task
    from opfor.scenarios.attacksurface.assets.domain.capabilities import http as cap_http
    from opfor.scenarios.attacksurface.assets.domain.capabilities.http import HarvestPaths
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData, Resolved

    world = World()
    world.add(Node(id="domain:h", type="domain", payload=DomainData(name="h", root="h", source="s")))
    world.absorb([Fact(kind="resolved", about="domain:h",
                       payload=Resolved(resolvable=True, addresses=("1.2.3.4",)))])

    def boom(_text):
        raise RuntimeError("harvest parse blew up")

    # an un-tolerated error outside the per-source guards, so the run must still emit the
    # harvested fact plus a gap, else a factless live host silently suppresses endpoint
    # enumeration for every host while the run still closes
    monkeypatch.setattr(cap_http, "cloud_refs_in_text", boom)
    out = HarvestPaths(lambda *a: {"text": "<html></html>"},
                       lambda *a: {"text": "<html></html>"}, lambda *a: set()).run(
        Task(capability="domain_harvest", node="domain:h"), world)
    assert isinstance(out, Done)
    kinds = {f.kind for f in out.facts}
    assert "harvested" in kinds and "coverage_gap" in kinds


def test_harvest_records_a_gap_when_the_home_document_is_unreachable():
    from opfor.core import Done, Fact, Task
    from opfor.scenarios.attacksurface.assets.domain.capabilities.http import HarvestPaths
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData, Resolved

    world = World()
    world.add(Node(id="domain:h", type="domain", payload=DomainData(name="h", root="h", source="s")))
    world.absorb([Fact(kind="resolved", about="domain:h",
                       payload=Resolved(resolvable=True, addresses=("1.2.3.4",)))])

    # fetch_document reports an unreachable host as a None status rather than raising. Harvest
    # must surface that as a coverage gap, not launder a transport failure into an empty
    # harvest that reads downstream as a host revealing no paths.
    unreachable = lambda *a: {"status": None, "reason": "unreachable", "text": ""}
    out = HarvestPaths(unreachable, unreachable, lambda *a: set()).run(
        Task(capability="domain_harvest", node="domain:h"), world)
    assert isinstance(out, Done)
    kinds = {f.kind for f in out.facts}
    assert "harvested" in kinds and "coverage_gap" in kinds

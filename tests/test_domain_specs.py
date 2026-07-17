from __future__ import annotations

import json

import pytest

from opfor.core import Budget, MockProvider, Node, Phase, Scope, World, run
from opfor.core.result import CLOSED
from opfor.scenarios.attacksurface import build
from opfor.scenarios.attacksurface.lifecycle.triage import TriageError, _finding_from_dict
from opfor.scenarios.attacksurface.types import Org

from tests.surface_fixtures import *


def test_openapi_spec_is_expanded_into_its_operations():
    world = _seed()
    _run(world)
    specs = [f.payload for f in world.facts("api_spec")]
    hit = [s for s in specs if s.base == "https://spa.example.com/openapi.json"]
    assert hit and hit[0].count == 2
    assert "GET /users" in hit[0].paths

def test_paths_from_openapi_names_methods():
    from opfor.scenarios.attacksurface.assets.domain.sources import paths_from_openapi

    doc = {"paths": {"/a": {"get": {}, "post": {}}, "/b": {"get": {}}}}
    assert set(paths_from_openapi(doc)) == {"GET,POST /a", "GET /b"}
    assert paths_from_openapi({}) == []
    assert paths_from_openapi({"paths": "not a map"}) == []

def test_info_from_openapi_reads_title_and_version():
    from opfor.scenarios.attacksurface.assets.domain.sources import info_from_openapi

    doc = {"openapi": "3.1.0", "info": {"title": "litellm api", "version": "1.90.0"}, "paths": {}}
    assert info_from_openapi(doc) == ("litellm api", "1.90.0")
    assert info_from_openapi({"swagger": "2.0", "info": {"title": "x"}}) == ("x", "")
    assert info_from_openapi({"paths": {}}) == ("", "")
    assert info_from_openapi("not a doc") == ("", "")

def test_openapi_paths_apply_the_declared_base_path():
    from opfor.scenarios.attacksurface.assets.domain.sources.parsers import paths_from_openapi
    # Swagger 2 basePath and OpenAPI 3 servers url both move an operation off the host root,
    # so the real unauthenticated surface is probed rather than a 404 at /users
    swagger = {"basePath": "/api/v2", "paths": {"/users": {"get": {}}}}
    assert "GET /api/v2/users" in paths_from_openapi(swagger)
    oas3 = {"servers": [{"url": "https://h/api/v3"}], "paths": {"/orders": {"get": {}}}}
    assert any(p.endswith("/api/v3/orders") and "GET" in p for p in paths_from_openapi(oas3))

def test_openapi_path_item_without_verbs_is_a_get_candidate_not_a_write():
    from opfor.scenarios.attacksurface.assets.domain.sources.parsers import (
        paths_from_openapi, split_operation)
    ops = paths_from_openapi({"paths": {"/ref-path": {"$ref": "#/components/x"}}})
    assert ops == ["GET /ref-path"]
    methods, path = split_operation(ops[0])
    assert "GET" in methods and path == "/ref-path"

def test_openapi_base_drops_a_protocol_relative_authority():
    from opfor.scenarios.attacksurface.assets.domain.sources.parsers import _openapi_base

    # //evil.com/api must keep only its path, never turn the authority into the base path
    assert _openapi_base({"servers": [{"url": "//evil.com/api"}]}) == "/api"
    assert _openapi_base({"servers": [{"url": "https://h/api/v2"}]}) == "/api/v2"
    assert _openapi_base({"basePath": "/v1"}) == "/v1"

def test_paths_from_openapi_caps_and_expand_spec_reports_the_drop():
    from opfor.core import Done, Task
    from opfor.scenarios.attacksurface.assets.domain.capabilities.specs import ExpandSpec
    from opfor.scenarios.attacksurface.assets.domain.sources.parsers import _MAX_SPEC_PATHS
    from opfor.scenarios.attacksurface.assets.domain.sources import paths_from_openapi
    from opfor.scenarios.attacksurface.assets.domain.types import Endpoint

    doc = {"paths": {f"/p{i}": {"get": {}} for i in range(_MAX_SPEC_PATHS + 300)}}
    parsed = paths_from_openapi(doc)
    assert len(parsed) == _MAX_SPEC_PATHS

    world = World()
    world.add(Node(id="endpoint:h/openapi.json", type="endpoint",
                   payload=Endpoint(url="https://h/openapi.json", path="/openapi.json",
                                    status=200, content_type="application/json")))
    import json as _json
    fetch = lambda host, path: {"status": 200, "text": _json.dumps(doc)}
    out = ExpandSpec(fetch).run(Task(capability="endpoint_expand_spec", node="endpoint:h/openapi.json"), world)
    assert isinstance(out, Done)
    gaps = [f.payload for f in out.facts if f.kind == "coverage_gap"]
    assert gaps and gaps[0].scan == "spec_parse", "a capped spec parse must report a coverage gap"

def test_split_operation_separates_methods_from_path():
    from opfor.scenarios.attacksurface.assets.domain.sources import split_operation

    assert split_operation("GET,POST /widgets") == (("GET", "POST"), "/widgets")
    assert split_operation("DELETE,GET /jobs/{job_id}") == (("DELETE", "GET"), "/jobs/{job_id}")
    assert split_operation("/bare-path") == ((), "/bare-path")

def test_probe_spec_verifies_reads_defers_writes_and_skips_templated():
    """A declared operation is not a reachable one, so ProbeSpec fetches each concrete GET
    and leaves write and templated operations for an authorized confirmation."""
    from opfor.core import Fact, Node, Task, World
    from opfor.scenarios.attacksurface.assets.domain.capabilities import ProbeSpec
    from opfor.scenarios.attacksurface.assets.domain.types import (
        APISpec, DomainData, Endpoint, Resolved,
    )

    calls = []

    def fetch(name, addresses, path):
        calls.append(path)
        if path.startswith("/opfor-baseline") or path.startswith("/does-not-exist"):
            return {"status": 404, "content_type": "", "body": "", "location": ""}
        if path == "/config/all":
            return {"status": 200, "content_type": "application/json",
                    "body": '{"ok":true}', "location": ""}
        if path == "/users":
            return {"status": 401, "content_type": "", "body": "", "location": ""}
        return {"status": 404, "content_type": "", "body": "", "location": ""}

    world = World()
    world.add(Node(id="domain:api.example.com", type="domain",
                   payload=DomainData(name="api.example.com", root="example.com", source="crt")))
    world.absorb([Fact(kind="resolved", about="domain:api.example.com",
                       payload=Resolved(resolvable=True, addresses=("203.0.113.5",), cnames=()))])
    ep_id = "endpoint:api.example.com/openapi.json"
    world.add(Node(id=ep_id, type="endpoint",
                   payload=Endpoint(url="https://api.example.com/openapi.json", path="/openapi.json",
                                    status=200, auth_required=False, content_type="application/json")))
    world.absorb([Fact(kind="api_spec", about=ep_id, payload=APISpec(
        base="https://api.example.com/openapi.json",
        paths=("GET /config/all", "GET /users", "POST /process", "DELETE,GET /jobs/{job_id}"),
        count=4))])

    out = ProbeSpec(fetch).run(Task(capability="endpoint_probe_spec", node=ep_id), world)

    facts = [f for f in out.facts if f.kind == "spec_audit"]
    assert len(facts) == 1
    ops = {op.path: op for op in facts[0].payload.operations}

    assert ops["/config/all"].verified and ops["/config/all"].status == 200
    assert not ops["/config/all"].auth_required and ops["/config/all"].distinct
    assert ops["/users"].verified and ops["/users"].auth_required
    assert not ops["/process"].verified and "write" in ops["/process"].reason
    assert not ops["/jobs/{job_id}"].verified and "templated" in ops["/jobs/{job_id}"].reason
    # A write operation and a templated path are never sent.
    assert "/process" not in calls
    assert "/jobs/{job_id}" not in calls

def test_spec_fetch_failure_still_closes_and_is_loud():
    def boom(name, path):
        raise TimeoutError("spec slow")

    scenario = _make(fetch_doc_fn=boom)
    world = _seed()
    report = run(scenario, world, scope=Scope(max_tier="recon", hosts=(ROOT,)), budget=Budget(2000))
    assert report.closed
    assert any("failed" in n and "endpoint_expand_spec" in n for n in report.notes)

def test_expand_spec_fails_loud_on_transport_failure_and_on_a_malformed_body():
    from opfor.core import Failed, Task
    from opfor.scenarios.attacksurface.assets.domain.capabilities.specs import ExpandSpec
    from opfor.scenarios.attacksurface.assets.domain.types import Endpoint

    world = World()
    world.add(Node(id="endpoint:h/openapi.json", type="endpoint",
                   payload=Endpoint(url="https://h/openapi.json", path="/openapi.json",
                                    status=200, content_type="application/json")))
    task = Task(capability="endpoint_expand_spec", node="endpoint:h/openapi.json")

    no_answer = ExpandSpec(lambda h, p: {"status": None, "text": ""}).run(task, world)
    assert isinstance(no_answer, Failed) and "no response" in no_answer.reason
    bad_json = ExpandSpec(lambda h, p: {"status": 200, "text": "<html>not a spec"}).run(task, world)
    assert isinstance(bad_json, Failed) and "not JSON" in bad_json.reason

def test_graphql_introspection_fact_reads_query_and_mutation():
    world = _seed()
    _run(world)
    schemas = [f.payload for f in world.facts("graphql")]
    hit = [s for s in schemas if s.enabled and s.count == 3]
    assert hit and "query:me" in hit[0].operations

def test_operations_from_introspection_reads_query_and_mutation():
    from opfor.scenarios.attacksurface.assets.domain.sources import operations_from_introspection

    data = {"__schema": {"queryType": {"fields": [{"name": "me"}]},
                         "mutationType": {"fields": [{"name": "login"}]}}}
    assert operations_from_introspection(data) == ["mutation:login", "query:me"]
    assert operations_from_introspection({}) == []

def test_graphql_capability_marks_an_errored_introspection_failed_not_disabled():
    from opfor.core import Failed, Task
    from opfor.scenarios.attacksurface.assets.domain.capabilities.specs import GraphQLIntrospect
    from opfor.scenarios.attacksurface.assets.domain.types import Endpoint

    world = World()
    world.add(Node(id="endpoint:h/graphql", type="endpoint",
                   payload=Endpoint(url="https://h/graphql", path="/graphql", status=200)))

    def introspect(host, path):
        raise RuntimeError("graphql introspection errored, HTTP 500")

    outcome = GraphQLIntrospect(introspect).run(
        Task(capability="endpoint_graphql", node="endpoint:h/graphql"), world)
    # an errored probe is a loud Failed, never a clean graphql-disabled fact
    assert isinstance(outcome, Failed) and "500" in outcome.reason

def test_nvd_cves_parses_id_score_severity_and_summary():
    from opfor.scenarios.attacksurface.assets.domain import sources as domains

    reply = {
        "vulnerabilities": [
            {"cve": {
                "id": "CVE-2021-39226",
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
                            "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}]},
                "descriptions": [{"lang": "es", "value": "ignore"}, {"lang": "en", "value": "auth bypass"}],
                "references": [{"url": "https://advisory.example/GHSA-1"}, {"url": "https://nvd.example/CVE-2021-39226"}],
            }},
            {"cve": {"id": "", "metrics": {}, "descriptions": []}},
        ]
    }
    cves = domains.cves_from_nvd(reply)
    assert len(cves) == 1
    # the strongest metric wins, v3.1 over v2, the english description is taken, and the
    # advisory links are kept so an exploit poc is anchored to a real source
    assert cves[0] == {
        "id": "CVE-2021-39226", "cvss": 9.8, "severity": "CRITICAL", "summary": "auth bypass",
        "references": ["https://advisory.example/GHSA-1", "https://nvd.example/CVE-2021-39226"]}

def test_nvd_cves_returns_nothing_for_an_unidentified_product():
    from opfor.scenarios.attacksurface.assets.domain import sources as domains

    # no product means nothing to query, an empty list without a network call
    assert domains.nvd_cves("", "1.0") == []

def test_nvd_keyword_search_uses_the_product_alone_not_the_version(monkeypatch):
    """NVD keyword search matches the description text, where a version rarely appears, so
    the query is the product alone, or a version-bearing product would return nothing."""
    from opfor.scenarios.attacksurface.assets.domain.sources import passive as domains

    queries = []
    monkeypatch.setattr(domains, "_nvd_fetch", lambda q: queries.append(q) or [])
    domains.nvd_cves("litellm", "1.90.0")
    assert queries == ["keywordSearch=litellm"]

def test_nvd_falls_back_to_a_product_keyword_when_the_cpe_match_is_empty(monkeypatch):
    """A wrong vendor guess or a cve not tagged with the cpe yields an empty cpe match, so
    the query falls back to a product keyword rather than missing a real advisory."""
    from opfor.scenarios.attacksurface.assets.domain.sources import passive as domains

    queries = []

    def fake_fetch(query):
        queries.append(query)
        if query.startswith("virtualMatchString"):
            return []
        return [{"id": "CVE-2026-40217"}]

    monkeypatch.setattr(domains, "_nvd_fetch", fake_fetch)
    result = domains.nvd_cves("litellm", "1.90.0", cpe="berriai:litellm")
    assert result == [{"id": "CVE-2026-40217"}]
    assert len(queries) == 2
    assert queries[0].startswith("virtualMatchString")
    assert queries[1] == "keywordSearch=litellm"

def test_nvd_cpe_match_with_results_does_not_fall_back(monkeypatch):
    from opfor.scenarios.attacksurface.assets.domain.sources import passive as domains

    queries = []
    monkeypatch.setattr(domains, "_nvd_fetch",
                        lambda q: queries.append(q) or [{"id": "CVE-2020-0001"}])
    result = domains.nvd_cves("grafana", "9.0.0", cpe="grafana:grafana")
    assert result == [{"id": "CVE-2020-0001"}]
    assert len(queries) == 1
    assert queries[0].startswith("virtualMatchString")

def test_nvd_throttle_serializes_calls_to_stay_under_the_rate_limit(monkeypatch):
    from opfor.scenarios.attacksurface.assets.domain.sources import passive as domains

    clock = {"t": 100.0}
    slept = []
    monkeypatch.setattr(domains.time, "monotonic", lambda: clock["t"])
    monkeypatch.setattr(domains.time, "sleep", lambda s: slept.append(s))
    domains._nvd_next[0] = 0.0

    # the first call does not wait, it only schedules the next slot
    domains._nvd_wait(6.0)
    assert slept == []
    # a second call before the interval has passed blocks until the slot opens
    domains._nvd_wait(6.0)
    assert slept and abs(slept[-1] - 6.0) < 0.01

def test_cve_scan_records_the_identified_product_and_its_cves():
    # the identify seam names the product, the cve seam looks it up, and the scan records
    # both as a raw fact, the agent-driven identification feeding the mechanical lookup
    def identify(evidence):
        assert "host" in evidence
        return {"product": "grafana", "version": "8.0.0", "cpe": "grafana:grafana"}

    def cves(product, version, cpe=""):
        assert (product, version, cpe) == ("grafana", "8.0.0", "grafana:grafana")
        return [{"id": "CVE-2021-39226", "cvss": 9.8, "severity": "CRITICAL", "summary": "auth bypass"}]

    report, _scenario, world = _run_capturing(identify_fn=identify, cve_fn=cves)
    scans = [f.payload for f in world.facts("cve_scanned") if f.payload.product]
    assert scans, "expected a cve_scanned fact carrying a product"
    assert scans[0].product == "grafana" and scans[0].version == "8.0.0"
    assert any(c.id == "CVE-2021-39226" and c.severity == "CRITICAL" for c in scans[0].cves)

def test_cve_scan_fails_loud_when_identification_errors():
    # a model or lookup error is a loud Failed, never a silent empty result, invariant 5
    def boom(evidence):
        raise RuntimeError("model down")

    report, _scenario, _world = _run_capturing(identify_fn=boom)
    assert any("cve_scan" in note and "model down" in note for note in report.notes)

def test_cve_evidence_surfaces_the_spec_version_from_the_endpoint_body():
    """The CVE identification reads a specification's declared version from the endpoint's
    own body head, before any separate parse runs, so a version-bearing spec is not missed."""
    from opfor.core import Node, Task, World
    from opfor.scenarios.attacksurface.assets.domain.capabilities import CveScan
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData, Endpoint

    captured = {}

    def identify(evidence):
        captured["evidence"] = evidence
        return {"product": "", "version": "", "cpe": ""}

    def cves(product, version, cpe=""):
        return []

    world = World()
    world.add(Node(id="domain:api.example.com", type="domain",
                   payload=DomainData(name="api.example.com", root="example.com", source="crt")))
    ep_id = "endpoint:api.example.com/openapi.json"
    body = '{"openapi":"3.1.0","info":{"title":"litellm api","version":"1.90.0"},"paths":{}}'
    world.add(Node(id=ep_id, type="endpoint",
                   payload=Endpoint(url="https://api.example.com/openapi.json", path="/openapi.json",
                                    status=200, auth_required=False,
                                    content_type="application/json", body=body)))

    out = CveScan(identify, cves).run(Task(capability="cve_scan", node="domain:api.example.com"), world)
    assert out.facts
    assert "1.90.0" in captured["evidence"]
    assert "litellm api" in captured["evidence"]

def test_cve_render_ranks_by_cvss_and_notes_truncation():
    from opfor.core import Fact
    from opfor.scenarios.attacksurface.assets.domain.types import CVE, CVEScan, DomainData, HTTP, Resolved
    from opfor.scenarios.attacksurface.render import SurfaceRenderer

    world = World()
    world.add(Node(id="domain:h", type="domain", payload=DomainData(name="h", root="h", source="s")))
    world.absorb([
        Fact(kind="resolved", about="domain:h", payload=Resolved(resolvable=True, addresses=("1.2.3.4",))),
        Fact(kind="http", about="domain:h", payload=HTTP(alive=True, status=200, url="https://h/")),
    ])
    # eleven CVEs, the critical one last in database order so a blind head slice would drop it
    cves = tuple(CVE(id=f"CVE-{i}", cvss=1.0, severity="LOW", summary="low") for i in range(10))
    cves += (CVE(id="CVE-CRIT", cvss=9.8, severity="CRITICAL", summary="rce"),)
    world.absorb([Fact(kind="cve_scanned", about="domain:h",
                       payload=CVEScan(product="acme", version="1.0", cves=cves))])
    report = "\n".join(SurfaceRenderer(clues=[], takeover=[]).units(world))
    # the highest-scored CVE reaches the report despite being last in database order
    assert "CVE-CRIT" in report
    # the truncation is stated rather than silent
    assert "more CVE(s) not shown" in report

from __future__ import annotations

from opfor.scenarios.attacksurface.assets.domain.sources.observations import Response
from opfor.core import Budget, Node, Scope, World, run

from tests.scenarios.attacksurface.fixtures import (
    HostScope,
    ROOT,
    _make,
    _run,
    _seed,
)


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
    fetch = lambda host, path: Response(status=200, body=_json.dumps(doc))
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

    def fetch(name, addresses, path, *, body_limit=None):
        calls.append(path)
        if path.startswith("/opfor-baseline") or path.startswith("/does-not-exist"):
            return Response(status=404)
        if path == "/config/all":
            return Response(status=200, content_type="application/json", body='{"ok":true}')
        if path == "/users":
            return Response(status=401)
        return Response(status=404)

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


def test_probe_spec_flags_a_coverage_gap_when_the_baseline_could_not_be_established():
    # regression: with no catch-all baseline, a distinct 200 cannot be told from a blanket-200
    # front, so a reachable operation is unfiltered and must be surfaced rather than presented as
    # a confirmed exposed operation, the same guard the endpoint probe applies
    from opfor.core import Fact, Node, Task, World
    from opfor.scenarios.attacksurface.assets.domain.capabilities import ProbeSpec
    from opfor.scenarios.attacksurface.assets.domain.types import (
        APISpec, DomainData, Endpoint, Resolved,
    )

    def fetch(name, addresses, path, *, body_limit=None):
        if path.startswith("/opfor-baseline") or path.startswith("/does-not-exist"):
            raise TimeoutError("baseline probe timed out")  # the catch-all baseline cannot be read
        if path == "/config/all":
            return Response(status=200, content_type="application/json", body="{}")
        return Response(status=404)

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
        base="https://api.example.com/openapi.json", paths=("GET /config/all",), count=1))])

    out = ProbeSpec(fetch).run(Task(capability="endpoint_probe_spec", node=ep_id), world)
    assert any(f.kind == "coverage_gap" for f in out.facts)

def test_spec_fetch_failure_still_closes_and_is_loud():
    def boom(name, path):
        raise TimeoutError("spec slow")

    scenario = _make(fetch_doc_fn=boom)
    world = _seed()
    report = run(scenario, world, scope=Scope(max_tier="recon", matcher=HostScope(hosts=(ROOT,))), budget=Budget(2000))
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

    no_answer = ExpandSpec(lambda h, p: Response(status=None)).run(task, world)
    assert isinstance(no_answer, Failed) and "no response" in no_answer.reason
    bad_json = ExpandSpec(lambda h, p: Response(status=200, body="<html>not a spec")).run(task, world)
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

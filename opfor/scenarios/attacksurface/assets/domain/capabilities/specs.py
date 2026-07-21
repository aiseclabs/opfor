"""ENRICH-phase API specification and GraphQL introspection capabilities."""

from __future__ import annotations

import json
from urllib.parse import urlparse

from opfor.core import Capability, Done, Fact, Failed, Outcome, Phase, Task, World
from opfor.scenarios.attacksurface.assets.domain.capabilities.failures import _coverage_gap, net_failed
from opfor.scenarios.attacksurface.assets.domain.capabilities.responses import _baseline, _distinct
from opfor.scenarios.attacksurface.assets.domain.capabilities.http import Endpoints
from opfor.scenarios.attacksurface.assets.domain.sources import (
    info_from_openapi,
    operations_from_introspection,
    paths_from_openapi,
    split_operation,
)
from opfor.scenarios.attacksurface.assets.domain.types import (
    APISpec,
    GraphQLSchema,
    SpecAudit,
    SpecOperation,
)

# The well-known locations the probe checks to discover an API specification, owned here with the
# capability that recognizes and parses one, so a spec location is not a loose entry in a global
# path list. The recognizer keys on a path carrying openapi, swagger, or api-docs, so these match.
SPEC_PROBE_PATHS = ("/swagger.json", "/swagger-ui.html", "/openapi.json", "/api-docs",
                    "/v2/api-docs", "/v3/api-docs", "/swagger/v1/swagger.json")
# The well-known location the probe checks to find a GraphQL endpoint, owned with the introspector.
GRAPHQL_PROBE_PATHS = ("/graphql",)


class ExpandSpec(Capability):
    """ENRICH: parse an exposed API specification into the operations it declares.

    A single exposed OpenAPI or Swagger document maps a whole unauthenticated API, so this
    fetches the full document, the probe kept only a head, and records the declared paths.
    Fetching the target's own file is a scoped recon act, so it carries the host for scope.
    """

    name = "endpoint_expand_spec"
    phase = Phase.ENRICH
    osint = False

    def __init__(self, fetch_doc_fn) -> None:
        self._fetch = fetch_doc_fn

    def run(self, task: Task, world: World) -> Outcome:
        endpoint = world.node(task.node).payload
        host = urlparse(endpoint.url).hostname or ""
        try:
            document = self._fetch(host, endpoint.path)
        except Exception as exc:
            return net_failed("spec fetch", exc)
        text = document.get("text") or ""
        if document.get("status") is None:
            # the endpoint probed reachable but the full document did not answer, a transport
            # failure, not a spec that declares nothing, so fail loud rather than drop it as a
            # count-0 spec the renderer silently discards, invariant 5
            return Failed(reason=f"spec fetch got no response for {endpoint.url}")
        try:
            parsed = json.loads(text) if text else {}
        except Exception as exc:
            return Failed(reason=f"spec body at {endpoint.url} was not JSON: {type(exc).__name__}")
        paths = paths_from_openapi(parsed)
        title, version = info_from_openapi(parsed)
        payload = APISpec(base=endpoint.url, paths=tuple(paths), count=len(paths),
                          title=title, version=version)
        facts = [Fact(kind="api_spec", about=task.node, payload=payload)]
        declared = len(parsed.get("paths")) if isinstance(parsed.get("paths"), dict) else 0
        if declared > len(paths):
            # the parse stopped at its ceiling, so more operations were declared than stored.
            # Say how many were dropped rather than let a capped spec read as the whole API
            # surface, invariant 5
            gap = _coverage_gap("spec_parse", host, declared, [
                f"{endpoint.url}: {declared - len(paths)} of {declared} declared operations "
                "beyond the parse ceiling were not recorded"])
            if gap is not None:
                facts.append(Fact(kind="coverage_gap", about=task.node, payload=gap))
        return Done(facts=tuple(facts))


class ProbeSpec(Capability):
    """ENRICH: verify the operations an exposed specification declares by a safe read.

    ExpandSpec records what a specification declares, this checks whether the declaration is
    reachable. Each declared GET with a concrete path is fetched once, up to a cap of
    `_MAX_OPERATIONS`, beyond which the unprobed tail is recorded as a coverage_gap rather than
    dropped silently. An operation is never reported reachable on the strength of the document
    alone. A write method, POST, PUT, PATCH, or DELETE, and a templated path are recorded declared
    but not probed, since sending them could change state, so that verdict is deferred to an
    authorized confirmation. Probing is a scoped GET recon act, so it carries the host for scope.
    """

    name = "endpoint_probe_spec"
    phase = Phase.ENRICH
    osint = False

    _MAX_OPERATIONS = 200

    def __init__(self, fetch_fn) -> None:
        self._fetch = fetch_fn

    def run(self, task: Task, world: World) -> Outcome:
        spec = world.latest("api_spec", task.node)
        if spec is None:
            return Failed(reason="no api_spec fact on the target node")
        endpoint = world.node(task.node).payload
        host = urlparse(endpoint.url).hostname or ""
        addresses = self._addresses(world, host)
        baseline = _baseline(self._fetch, Endpoints._BASELINE_PATHS, host, addresses)
        operations: list[SpecOperation] = []
        for entry in list(spec.payload.paths)[: self._MAX_OPERATIONS]:
            methods, path = split_operation(entry)
            joined = ",".join(methods)
            if not path.startswith("/") or "{" in path or "}" in path:
                operations.append(SpecOperation(path=path, methods=joined,
                                                reason="templated or relative path, not probed"))
                continue
            if "GET" not in methods:
                operations.append(SpecOperation(path=path, methods=joined,
                                                reason="write operation, not probed without authorization"))
                continue
            try:
                result = self._fetch(host, addresses, path)
            except Exception as exc:
                operations.append(SpecOperation(path=path, methods=joined,
                                                reason=f"probe error {type(exc).__name__}"))
                continue
            status = result.get("status")
            if status is None:
                operations.append(SpecOperation(path=path, methods=joined, reason="no response"))
                continue
            operations.append(SpecOperation(
                path=path, methods=joined, verified=True, status=status,
                auth_required=status in (401, 403),
                distinct=_distinct(result, baseline),
                location=str(result.get("location", "")),
                content_type=str(result.get("content_type", "")),
            ))
        payload = SpecAudit(base=endpoint.url, operations=tuple(operations))
        facts: list[Fact] = [Fact(kind="spec_audit", about=task.node, payload=payload)]
        if baseline.get("status") is None and any(op.verified for op in operations):
            # The catch-all baseline could not be established, so a distinct 200 cannot be told from
            # a blanket-200 front, and every operation marked reachable here is unfiltered. Say so
            # rather than let a blanket-200 host read as a set of confirmed exposed operations, the
            # same guard the endpoint probe applies, invariant 5.
            gap = _coverage_gap("spec_probe", host, len(operations),
                                ["baseline could not be established, operation distinctness is unreliable"])
            if gap is not None:
                facts.append(Fact(kind="coverage_gap", about=task.node, payload=gap))
        total = len(spec.payload.paths)
        if total > self._MAX_OPERATIONS:
            # The audit is capped, so the tail of a large spec is unprobed. Record why rather than
            # let a run close with declared operations silently unverified, the same capped-scan
            # disclosure ExpandSpec and Endpoints make, invariant 5.
            gap = _coverage_gap("spec_probe", host, total - self._MAX_OPERATIONS,
                                [f"only the first {self._MAX_OPERATIONS} of {total} declared operations were probed"])
            if gap is not None:
                facts.append(Fact(kind="coverage_gap", about=task.node, payload=gap))
        return Done(facts=tuple(facts))

    def _addresses(self, world: World, host: str):
        """The resolved public addresses of the spec's host, read from its domain node."""
        for node in world.nodes("domain"):
            if node.payload.name == host:
                resolved = world.latest("resolved", node.id)
                return resolved.payload.addresses if resolved else ()
        return ()


class GraphQLIntrospect(Capability):
    """ENRICH: introspect an open GraphQL endpoint into the operations it exposes.

    Introspection enabled in production maps the entire API, so this sends one read-only
    introspection query and records whether it answered and the operations it named.
    Sending the query touches the target, so it carries the host for scope.
    """

    name = "endpoint_graphql"
    phase = Phase.ENRICH
    osint = False

    def __init__(self, introspect_fn) -> None:
        self._introspect = introspect_fn

    def run(self, task: Task, world: World) -> Outcome:
        endpoint = world.node(task.node).payload
        host = urlparse(endpoint.url).hostname or ""
        try:
            schema = self._introspect(host, endpoint.path)
        except Exception as exc:
            return net_failed("graphql introspection", exc)
        operations = operations_from_introspection(schema) if schema else []
        payload = GraphQLSchema(enabled=bool(schema), operations=tuple(operations),
                                count=len(operations))
        return Done(facts=(Fact(kind="graphql", about=task.node, payload=payload),))

---
title: Information exposure of the API surface or schema
impact: MEDIUM
tags: [cwe-200, owasp-a05]
clues:
- id: swagger-openapi
  note: a Swagger or OpenAPI document is served, it maps the whole API surface
  path: /swagger.json
  body_contains: swagger
  content_type: json
- id: openapi-spec
  note: an OpenAPI document is served, it maps the whole API surface
  path: /openapi.json
  body_contains: openapi
  content_type: json
---

# Information Exposure Of The API Surface Or Schema

A machine-readable description of a service's own surface, served to anyone, that hands an attacker a
map they would otherwise have to guess. An OpenAPI or Swagger document lists every route, its
parameters, and its auth requirement. A GraphQL introspection reply returns the whole type system,
every query, every mutation, every field. Neither is an exploit on its own, both are a force
multiplier, they turn blind enumeration into a targeted read of exactly which endpoints exist and
which of them mutate state. This class judges that the map is served, and how much of what it
describes is itself reachable without a credential.

## Signals

- A clue hit for a spec document, a `/swagger.json` or `/openapi.json` that answers `200` with a
  JSON body naming `swagger` or `openapi`. A spec served at any path, not only the two probed, is
  the same signal, the document is the finding, not the path it sits at.
- A `graphql` fact on a host, a `/graphql` endpoint that answers a POST introspection query with a
  populated `__schema`, a non-zero count of query and mutation operations. Introspection left on in
  production is the exposure, a schema that names mutations is a live map of state-changing calls.

## Grading Levers

The spec or schema is the map. Grade on how much of what it describes an attacker can actually
reach, mirroring the reachable-versus-declared reasoning below.

- A schema whose mutations, the state-changing operations, answer without a credential ranks above
  one that exposes only read types, which ranks above a spec whose every declared route still
  refuses unauthenticated.
- The spec's own exposure is at most medium on its own, it becomes the lead-in to a missing-
  authentication finding on each declared route that in fact answers unguarded.

## Declared Is Not Reachable

A route named in a spec is a claim, not a live door. Sort what the document declares into three
groups and grade only the first, do not report a declared route as exposed without probing it.

- Reachable unauthenticated, the route answers with data and no credential, this is the finding.
- Gated, the route answers `401` or `403` or redirects to a sign-in, note it as attack surface, not
  as an exposure.
- Not probed, the route is only declared, say so plainly, never grade a route the run did not reach.

## Positive And Negative Examples

- Positive. `GET /openapi.json` answers `200` with `{"openapi":"3.0.1","paths":{"/internal/users":
  ...}}`, and `GET /internal/users` then answers `200` with a user list, the map and a reachable
  route it named. Positive. `POST /graphql` with `{"query":"{__schema{mutationType{fields{name}}}}"}`
  returns a list of mutations, introspection serving a state-changing surface map.
- Negative. `GET /openapi.json` answers `200` but every path it declares answers `401`, the map is
  served yet nothing it names is reachable, note the surface, do not grade a route as exposed.
  Negative. `POST /graphql` answers `400` with `introspection is disabled`, no schema returned.

## Not A Finding

- A spec whose declared routes are all gated is attack surface, not an exposure of data, keep it low
  and factual, do not inflate a map into a breach.
- A `graphql` endpoint that refuses introspection returns no schema, there is nothing exposed.
- The shared false-positive traps apply, a refusal, a redirect, and an empty catch-all body are not
  an exposed document.

## Evidence And PoC

For a spec, cite the path, the `200`, and the field that identifies it, `swagger` or `openapi`, and
list the declared routes the run actually probed with each one's status. For introspection, the PoC
is the safe read
`curl -s -X POST <url> -H 'content-type: application/json' -d '{"query":"{__schema{queryType{name}}}"}'`
and the operation counts it returned. The PoC reads the map, it never drives a route the map names.

---
title: Exposed API specification
impact: MEDIUM
triggers:
- openapi
- swagger
- api-docs
- api_spec
clues:
- id: swagger-openapi
  note: a Swagger specification is present, it maps the API surface
  path: /swagger.json
  body_contains: swagger
  content_type: json
- id: openapi-spec
  note: an OpenAPI specification is present, it maps the API surface
  path: /openapi.json
  body_contains: openapi
  content_type: json
---

# Exposed API Specification

A machine-readable API description, OpenAPI or Swagger, served without authentication. One
exposed specification maps a whole unauthenticated API surface, every operation, path, and
parameter, so it is a single finding that stands in for many endpoints an attacker would
otherwise have to guess.

## Signals

- A path such as `/openapi.json`, `/swagger.json`, `/v2/api-docs`, `/swagger/v1/swagger.json`
  answering with JSON whose body carries `openapi` or `swagger` and a `paths` object.
- A parsed specification fact in the surface that reports a non-zero operation count. The
  count is the size of the mapped surface, so a spec that declares many operations is a
  larger exposure than one that declares none.

An empty or zero-operation specification maps nothing, so it is not itself a finding.

## Declared Is Not Reachable

A specification declares operations, it does not prove they answer without authentication. A
declared operation and a reachable one are different claims, so do not grade an operation as
open on the strength of the document alone. The safe-read verification in the surface is
what tells them apart, it probes each declared GET with a concrete path and reports three
groups.

- Reachable unauthenticated. A GET that answered 2xx with real content, distinct from the
  host's catch-all. This is verified exposure, the operation returns data to anyone. Grade
  on what it returns.
- Gated. A GET the host refused with 401 or 403 or sent to an identity redirect. The
  declaration is public but the operation is not reachable, so it is not itself an exposure.
- Not probed. A write operation, POST, PUT, PATCH, or DELETE, or a templated path. These are
  not sent during reconnaissance, since a write could change state. Report them as a surface
  that needs an authorized confirmation, never as confirmed open.

## Grading

Medium by default when the specification is public but its operations are gated or unproven,
the spec maps the surface but is not itself the data. Grade up when the verification shows
operations reachable without authentication, higher when those return sensitive data.
Unauthenticated write operations are the strongest case, but if they were only declared and
not verified, say so and mark them for authorized confirmation rather than asserting they
are open.

## Evidence And PoC

Cite the specification URL, the operation count, and the verified breakdown, how many
operations answered without authentication and which. The PoC is a safe read of the spec,
`curl -s <url>`, and for a reachable operation the exact GET that returned data. Do not
exercise write operations here, note that an operator can confirm them under authorization.

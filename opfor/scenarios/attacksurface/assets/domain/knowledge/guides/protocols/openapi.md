---
title: OpenAPI and Swagger
kind: protocol
detect:
  markers: [swagger, openapi, "api-docs", "swagger-ui", redoc, '"paths":']
---

# OpenAPI And Swagger

A machine-readable description of an HTTP API, served as a JSON or YAML document, sometimes behind a
rendered explorer such as Swagger UI or ReDoc. It is the single most useful recon artifact a service
can leak, it names every route, every parameter, and often which routes require authentication and
which do not, so it turns blind enumeration into a targeted read.

## On The Recon Surface

- A document at `/swagger.json`, `/openapi.json`, `/v2/api-docs`, `/v3/api-docs`, or an arbitrary
  path, whose body carries `openapi` or `swagger` and a `paths` object. The path varies, the
  document is the signal.
- A rendered explorer page, Swagger UI or ReDoc, that loads a spec URL, so the spec is one fetch
  away even when the JSON path is not the default.
- A `securitySchemes` or per-path `security` block, which states which routes the service itself
  believes are gated, a claim to check against what actually answers.

## How To Read It

The spec is a claim, not a live door. Sort the routes it declares into reachable-unauthenticated,
gated, and not-probed, and grade only the first. A route the run never probed is declared, not
exposed, say so. The spec's own exposure is at most a map, it becomes the lead-in to a per-route
missing-authentication finding on each declared route that in fact answers unguarded.

## Feeds

- `information-exposure`, the served spec as a surface map, graded by how much of it is reachable.
- `missing-authentication`, each declared route that answers without a credential.

## Traps

A spec served while every route it declares still answers `401` is attack surface, not a breach, do
not inflate the map into an exposure of data.

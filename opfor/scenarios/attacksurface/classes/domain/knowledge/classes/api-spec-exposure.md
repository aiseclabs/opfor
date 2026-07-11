---
title: Exposed API specification
impact: MEDIUM
triggers:
  - openapi
  - swagger
  - api-docs
  - api_spec
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

## Grading

Medium by default, the specification maps the surface but is not itself the data. Grade up
when the operations it declares include unauthenticated writes or clearly sensitive reads.

## Evidence And PoC

Cite the specification URL and the operation count. The PoC is a safe read of the spec,
`curl -s <url>`, then a note that an operator can enumerate and exercise the declared
operations from it. Do not exercise them here.

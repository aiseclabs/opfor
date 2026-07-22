---
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

# API Specification Clues

Matchers that surface a declared API specification for the `api-spec-exposure` finding.

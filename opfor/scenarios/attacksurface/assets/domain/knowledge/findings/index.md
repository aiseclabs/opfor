# Findings

The finding classes triage may mint, one file each. The body is the judgment prose the model-backed
triage weighs, so what counts as real and how severe is prose, not a keyword list in code. A class
that surfaces its own deterministic evidence carries it in frontmatter, a `clues` list or a
`signatures` table, which the capability records and triage reads, never interprets, invariant 1.

- `api-spec-exposure.md` An OpenAPI or Swagger specification served without authentication, mapping
  the API surface in one document.
- `exposed-admin-interface.md` An administrative console or a directory listing reachable without
  authentication.
- `graphql-introspection.md` A GraphQL endpoint that answers introspection and hands back its whole
  schema.
- `improper-authentication.md` An authentication control that is missing, weak, or bypassable.
- `known-vulnerability.md` A running version the CVE lookup tied to a known vulnerability, graded and
  grounded from the product's own knowledge.
- `open-source-service-exposure.md` An open-source service exposing its console or an
  unauthenticated endpoint such as a Spring actuator.
- `subdomain-takeover.md` A dangling CNAME to a deprovisioned service a third party can claim, with
  the per-provider takeover signatures in frontmatter.
- `unauthenticated-interface.md` An interface reachable without the authentication it should require.

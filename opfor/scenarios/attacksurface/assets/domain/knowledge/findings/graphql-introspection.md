---
title: GraphQL introspection enabled
impact: MEDIUM
---

# GraphQL Introspection Enabled

A GraphQL endpoint that answers an introspection query returns its whole schema, every
type, query, and mutation. Like an exposed specification, this maps the entire API in one
response, so it is one finding that reveals the full surface.

## Signals

- A `graphql` fact in the surface reporting introspection enabled and a non-zero operation
  count. The count is the number of schema fields the introspection named.
- An endpoint at a `/graphql` path that answered a POST introspection with a schema.

Introspection that named no operation is not usable introspection. An endpoint can answer
a POST yet refuse the schema, so report only when the schema really came back with
operations in it.

## Grading

Grade on the shared severity rubric. The class-specific lever is the schema, an introspection
that exposes mutations or clearly sensitive query fields ranks above one that reveals only
public read types.

## Evidence And PoC

Cite the endpoint URL and the operation count. The PoC is the introspection query itself,
a safe read:
`curl -s -X POST <url> -H 'content-type: application/json' -d '{"query":"{__schema{queryType{name}}}"}'`.
Do not call the mutations it reveals.

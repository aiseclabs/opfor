---
title: GraphQL
kind: protocol
detect:
  markers: [graphql, __schema, __type, "querytype", "mutationtype", "graphiql"]
---

# GraphQL

A single endpoint, usually `/graphql`, that serves many operations over one transport. Its
distinctive recon surface is introspection, a built-in query that returns the whole type system,
every query, every mutation, every field. Left on in production, introspection is a live, exact map
of the API, including the state-changing operations a REST surface would hide behind many paths.

## On The Recon Surface

- A `/graphql` endpoint that answers a POST with a JSON body, or a GraphiQL or Apollo explorer page
  served on a GET.
- An introspection reply, a populated `__schema` with a non-zero count of query and mutation
  operations, returned to an unauthenticated POST.
- A schema whose `mutationType` names state-changing operations, the highest-value part of the map.

## How To Read It

Introspection returning a schema is the exposure, and a schema that names mutations ranks above one
that exposes only read types, which ranks above an endpoint that refuses introspection entirely.
Authorization in GraphQL is enforced per resolver, so a reachable schema does not prove the
operations run unauthenticated, it proves the map is served. Grade the map, then probe whether the
operations it names answer without a credential.

## Feeds

- `information-exposure`, introspection serving the schema, graded up when mutations are exposed.
- `missing-authentication`, an operation the schema names that answers with data and no credential.

## Traps

A `/graphql` endpoint that answers a probe with `introspection is disabled` or a `400` returns no
schema, there is nothing exposed. A GraphiQL page that will not load a schema is a console, not a
leak.

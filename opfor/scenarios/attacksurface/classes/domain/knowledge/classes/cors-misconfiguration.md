---
title: CORS misconfiguration
impact: MEDIUM
triggers:
  - access-control-allow-origin
  - access-control-allow-credentials
---

# CORS Misconfiguration

A cross-origin resource sharing policy that lets an untrusted site read authenticated
responses. The signal is in the response headers already captured, an
`access-control-allow-origin` and an `access-control-allow-credentials`. The policy is a
finding only when it actually widens who can read protected data, so this class is where
the judge tells a permissive-but-safe policy from a dangerous one.

## What Rises To A Finding

- `access-control-allow-origin: *` together with `access-control-allow-credentials: true`.
  A wildcard origin with credentials is the classic dangerous case, any site could read the
  authenticated response. High.
- An origin that is reflected back verbatim together with credentials allowed, since the
  server trusts any origin that asks. High.
- A trusted origin that is too broad, a `null` origin allowed, or a sibling wildcard such as
  `*.example.com` on a host that serves authenticated data. Medium, judge by what is behind
  it.

## What Is Not A Finding

- `access-control-allow-origin: *` on a public, unauthenticated resource with no
  credentials allowed. A public API or a static asset meant for any origin is not a leak.
- A response that carries no credentials and no protected data, the policy exposes nothing.

## Evidence And PoC

Quote the `access-control-allow-origin` and `access-control-allow-credentials` headers seen.
A safe read is `curl -sI -H 'Origin: https://evil.example' <url>` to show the origin is
reflected and credentials are allowed, never an actual cross-origin credential read.

---
title: OAuth
kind: protocol
detect:
  markers: ["response_type=", "client_id=", oauth, "/authorize"]
---

# OAuth

The delegated-authorization protocol behind most sign-in flows. On recon it is how a host proves it
is gated, a redirect to an authorization server, and it carries its own flow-parameter surface that
says how the grant is done and whether it is done well.

## On The Recon Surface

- A `302` or `303` redirect to an authorization server, `accounts.google.com`,
  `login.microsoftonline.com`, an Okta org, or a self-hosted `/authorize` endpoint, carrying a
  `client_id` and a `response_type`, the mark of a gated host.
- A `response_type=token` or an implicit-flow parameter, an older grant that returns a token in the
  URL fragment, weaker than an authorization-code grant with PKCE.

## How To Read It

A per-request proxy that stamps every request, Google IAP or Cloudflare Access, gates the whole
host. An application OAuth login only covers the routes the application sends through it, so a root
redirect is not a clean bill, an API or a background route may skip it. Distinguish the two by
whether a proxy assertion header or team cookie is present, not by the redirect alone.

## Feeds

- `improper-authentication`, a gate that appears present but does not cover the whole host, or a
  weak or bypassable flow.

## Traps

A redirect to an authorization server is the target doing the right thing, report it at most INFO to
record the host is gated. Raise only when an operation answers with content instead of the redirect.

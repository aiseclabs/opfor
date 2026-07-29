---
title: OAuth and OpenID Connect
kind: protocol
detect:
  markers: ["/.well-known/openid-configuration", "response_type=", id_token, "client_id=", oauth, openid, "authorization_endpoint"]
---

# OAuth And OpenID Connect

The delegated-authorization and identity protocols behind most sign-in flows. On recon they matter
in two ways, they are how a host proves it is gated, a redirect to an identity provider, and they
carry their own exposure and misconfiguration surface, a discovery document and flow parameters that
say how authentication is done and whether it is done well.

## On The Recon Surface

- A `302` or `303` redirect to an identity provider, `accounts.google.com`,
  `login.microsoftonline.com`, an Okta org, or a self-hosted `/authorize` endpoint, carrying a
  `client_id` and a `response_type`, the mark of a gated host.
- A discovery document at `/.well-known/openid-configuration`, which enumerates the endpoints and
  the supported flows, useful orientation and occasionally an exposure of an internal issuer URL.
- A `response_type=token` or an implicit-flow parameter, an older flow that returns a token in the
  URL fragment, weaker than an authorization-code flow with PKCE.

## How To Read It

A per-request proxy that stamps every request, Google IAP or Cloudflare Access, gates the whole
host. An application OAuth or OIDC login only covers the routes the application sends through it, so
a root redirect is not a clean bill, an API or a background route may skip it. Distinguish the two
by whether a proxy assertion header or team cookie is present, not by the redirect alone.

## Feeds

- `improper-authentication`, a gate that appears present but does not cover the whole host, or a
  weak or bypassable flow.
- `information-exposure`, a discovery document that leaks internal issuer or endpoint detail.

## Traps

A redirect to an identity provider is the target doing the right thing, report it at most INFO to
record the host is gated. Raise only when an operation answers with content instead of the redirect.

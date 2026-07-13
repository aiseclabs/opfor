---
title: Zero-trust proxy fronting
impact: INFO
triggers:
  - redirect to
  - iap
  - cloudflareaccess
  - accounts.google
  - login.microsoftonline
  - okta
---

# Zero-Trust Proxy Fronting

A host can sit behind an identity-aware proxy or a zero-trust gateway that authenticates
every request before the service behind it is reached. Google IAP, Cloudflare Access, Azure
AD Application Proxy, and an Okta or generic SSO gateway all work this way. The service is
not directly exposed, the gate is. So this class is how the judge tells a gated host from an
open one, and a gated host is reported at most as INFO, never as an open interface.

## How To Identify The Signal

Read the evidence, never guess from a host name.

- A 302 or 303 whose redirect target is an identity provider, such as `accounts.google.com`,
  a `cloudflareaccess.com` team domain, `login.microsoftonline.com`, an Okta org, or a
  self-hosted SSO or OpenID path the application sends every visitor to.
- A response header or cookie a proxy stamps, such as an IAP assertion header, a Cloudflare
  Access cookie, or a `WWW-Authenticate` challenge the gateway returns.
- A login or consent page served for the root itself rather than for one deep path, so the
  whole host sits behind the gate.

## What Rises To A Finding

The proxy being present is not itself a finding, it is the target doing the right thing.
Report INFO to record that the host exists and is gated, so the inventory stays honest.
Raise above INFO only when the evidence shows the gate is bypassable or misconfigured, for
example a path that reaches the service without the redirect, a health or metrics route the
proxy forgot to cover, or an error that leaks internal detail before the gate.

## What Is Not A Finding

- A cleanly gated host where every path redirects to the identity flow. This is protected.
- A single sign-on login page with no reachable content behind it on the paths seen.

## Evidence And PoC

Cite the redirect target or the proxy header that shows the gate. A safe read is
`curl -sI <url>` to show the redirect, never an attempt to bypass it.

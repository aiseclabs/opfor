---
title: Improper authentication
impact: INFO
---

# Improper Authentication

This class judges whether a host's perimeter authentication actually covers it. A per-request
zero-trust proxy such as Google IAP, Cloudflare Access, or Azure AD Application Proxy that
fronts every path is the target doing the right thing. The finding is when that gate is
absent, weaker than it looks, or bypassable, so an interface answers without it.

A host can sit behind a gate that stands in front of the service. Two kinds of gate exist
and they do not carry the same assurance, so the judge must tell them apart.

A per-request proxy authenticates every request in front of the service, so a host behind
one is gated on all paths at once. Google IAP, Cloudflare Access, and Azure AD Application
Proxy are this kind. When the evidence names one, the whole host is gated and reported at
most as INFO, and its individual interfaces need no separate check.

An application single sign-on is weaker. An Okta or self-hosted SSO login the application
itself redirects to, an appliance SSO such as a Jamf or a vendor login, only covers the
paths the application routes through it. It does not prove every interface is gated. An API
route, a health or metrics path, or a background endpoint may skip the redirect and answer
directly, and the SSO product itself may carry a known authentication bypass. So for an SSO
host, a redirect on the root is not a clean bill for the whole host, the individual
operations still have to be verified, and any operation that answers with content instead
of the SSO redirect is a gap to raise, not to wave through.

## How To Identify The Signal

Read the evidence, never guess from a host name.

- A 302 or 303 whose redirect target is an identity provider, such as `accounts.google.com`,
  a `cloudflareaccess.com` team domain, `login.microsoftonline.com`, an Okta org, or a
  self-hosted SSO or OpenID path the application sends every visitor to.
- A response header or cookie a proxy stamps, such as an IAP assertion header, a Cloudflare
  Access cookie, or a `WWW-Authenticate` challenge the gateway returns.
- A login or consent page served for the root itself rather than for one deep path, so the
  whole host sits behind the gate.
- A proxy assertion header or team cookie names a per-request proxy, so the gate is on all
  paths. The absence of one, with only an application redirect, points to an SSO that covers
  only what the application routes.

## What Rises To A Finding

The gate being present is not itself a finding, it is the target doing the right thing.
Report INFO to record that the host exists and is gated, so the inventory stays honest.
Raise above INFO when the evidence shows the gate is bypassable or does not cover the whole
host, for example an operation that answers with content instead of the redirect, a health
or metrics route the gate forgot to cover, or an error that leaks internal detail before the
gate. For an application SSO host this bar is lower, since it does not cover every route by
construction, so a verified operation that answered without the redirect is a real gap, and
a known authentication bypass in the named SSO product is worth reporting.

## What Is Not A Finding

- A host behind a per-request proxy, Google IAP, Cloudflare Access, or Azure AD Application
  Proxy, where the proxy header or cookie is present. The whole host is gated.
- An application SSO host where the operations that were actually probed all redirected to
  the identity flow and none answered with content. Judge on what was verified, not on the
  root redirect alone.

## Evidence And PoC

Cite the redirect target or the proxy header that shows the gate. A safe read is
`curl -sI <url>` to show the redirect, never an attempt to bypass it.

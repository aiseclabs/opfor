---
title: False-positive traps
---

# False-Positive Traps

The recurring ways a surface looks like a finding and is not. The challenger checks a claimed
finding against this list and the finder weighs it before claiming. Each trap names the
controlling fact that settles it, so a call rests on evidence rather than on a path or a name. A
finding survives a trap only when the evidence answers its controlling fact.

## The Traps

- Single-page-app shell. Many applications answer 200 with the same HTML for almost any path,
  so a 200 alone is weak evidence. Controlling fact, the response body or content type is
  specific to the path, a JSON payload, a distinct title, or real data, not the app's catch-all
  shell. The surface report already marks a response as distinct from the host's baseline
  catch-all, so trust that mark.
- Redirect to a sign-in flow. A 3xx whose location points at a login, a single-sign-on, an
  OAuth, an OpenID, or an account flow is the application protecting the interface behind it, so
  the redirect is not itself an exposure. Controlling fact, the location target.
- Server refusal. A 401 or a 403 is the server refusing, so the resource is already protected.
  Controlling fact, the status code.
- Refusing body. A body that says unauthorized, forbidden, access denied, or that the visitor
  must sign in is the application enforcing authentication in the body. Controlling fact, the
  body text refuses rather than serves. A page that merely links a login while serving content
  is not refusing.
- Public by design. A marketing home page, `/robots.txt`, `/sitemap.xml`,
  `/.well-known/security.txt`, or a documented public API endpoint is public by design and meant
  to be reachable. Controlling fact, what the surface serves, not that a path was reachable.
- Name or path keyword. A word such as admin, staging, or backup in a name or a path is a hint,
  not a finding. Controlling fact, the response content and status, a page that confirms the
  nature, not the keyword alone.
- Declared is not reachable. A specification, an introspection schema, or a version banner
  declares a surface, it does not prove an operation answers or that an instance is exploitable.
  Controlling fact, a safe read that reached the operation, not the declaration.
- Root redirect is not whole-host coverage. An application single-sign-on redirect on the root
  covers only the paths the application routes through it, so an API, a health, or a metrics
  path may still answer directly. A per-request proxy such as Google IAP, Cloudflare Access, or
  Azure AD Application Proxy does cover every path, named by its assertion header or team cookie.
  Controlling fact, which kind of gate the evidence names.
- Liveness probe. A health or readiness endpoint that answers only a bare status, a
  `{"status":"UP"}` or an `ok`, is meant to be reachable and leaks no internal detail, so it is
  not an information exposure. Controlling fact, the body carries only liveness, not versions,
  configuration, dependency names, or internal hostnames. A health endpoint that dumps build
  detail or component internals is judged on what it serves, not on its name.

---
title: Unauthenticated interface
impact: INFO
always: true
triggers:
  - endpoint
---

# Unauthenticated Interface

An interface the operator can reach over HTTP without presenting a credential. Reaching
one is the base observation of this scenario. Most reachable paths are meant to be public
and are inventory, not a risk, so the judgment is not "is it reachable" but "should this
be reachable unauthenticated, and does reaching it hand an attacker something".

## What Rises To A Finding

Report an unauthenticated interface when it exposes function or data that a public
visitor should not drive: an internal or administrative action, a data read that is not a
public page, a management or debug surface, an API that mutates state. The severity
follows what the interface grants. A read-only info leak is low, an unauthenticated
management or write surface is high.

## What Is Not A Finding

Do not report a path that is public by design or that the application in fact protects.
The signal is the response, not the path name.

- A page meant to be public: a marketing home page, `/robots.txt`, `/sitemap.xml`,
  `/.well-known/security.txt`, a documented public API endpoint. Reachable is correct.
- A protected resource that enforces auth. A 401 or 403 is the server refusing, so it is
  already protected, not open. A capability marks these `auth_required`, and they are not
  offered to you, but judge on the same principle if one appears.
- A redirect to a sign-in or identity flow. A 3xx whose `location` points at a login,
  single-sign-on, OAuth, OpenID, or account flow is the application sending an
  unauthenticated visitor to authenticate. The interface behind it is protected, so the
  redirect itself is not an exposure.
- A body that plainly refuses. A response whose text says the request is unauthorized,
  forbidden, access is denied, or the visitor must sign in is the application enforcing
  auth in the body. It is protected, not open. A page that merely links a login while
  serving its content is not refusing, judge that on its content.
- A single-page-app shell. Many apps answer 200 with the same HTML for almost any path,
  so a 200 alone is weak evidence. Look for a response whose body or content type is
  specific to the path, a JSON payload, a distinct title, real data, before calling it a
  live interface rather than the app's catch-all shell.

## Evidence And PoC

Cite the status, the path, and what in the body shows it is a real interface rather than a
shell or a refusal. The PoC is a safe read that demonstrates reachability, never an
attack: `curl -s <url>`, then note what an operator should confirm should be public.

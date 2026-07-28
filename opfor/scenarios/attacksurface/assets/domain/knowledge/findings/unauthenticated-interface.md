---
title: Unauthenticated interface
impact: INFO
---

# Unauthenticated Interface

An interface the operator can reach over HTTP without presenting a credential. Reaching
one is the base observation of this scenario. Most reachable paths are meant to be public
and are inventory, not a risk, so the judgment is not "is it reachable" but "should this
be reachable unauthenticated, and does reaching it hand an attacker something".

## What Rises To A Finding

Report an unauthenticated interface when it exposes function or data that a public
visitor should not drive: an internal or administrative action, a data read that is not a
public page, a management or debug surface, an API that mutates state. Grade on the shared
severity rubric, what the interface grants sets its ceiling.

## What Is Not A Finding

The signal is the response, not the path name. The recurring look-alikes, a public-by-design
page, a 401 or 403 refusal, a redirect to a sign-in flow, a refusing body, and a
single-page-app catch-all shell, are the shared false-positive traps, judge against those. One
class note, a capability marks a resource that already refused with a credential challenge as
`auth_required` and does not offer it here, so a resource that reaches you is one that answered.

## Evidence And PoC

Cite the status, the path, and what in the body shows it is a real interface rather than a
shell or a refusal. The PoC is a safe read that demonstrates reachability, never an
attack: `curl -s <url>`, then note what an operator should confirm should be public.

---
title: Exposed non-production or admin interface
impact: MEDIUM
always: true
triggers:
- admin
- staging
- internal
---

# Exposed Non-Production Or Admin Interface

A live, internet-facing host whose nature makes it a foothold worth reducing even before a
specific flaw is found: an administrative console, a staging or test deployment, an
internal tool, or an infrastructure management surface. These are reported as a MEDIUM
because an attacker treats them as softer targets, often weaker auth, debug on, or real
data in a non-production copy.

## Signals

The subdomain name or the page is the tell. Names and titles that suggest this class:

- Administration and management: admin, dashboard, portainer, phpmyadmin, adminer,
  gateway, sso.
- Non-production: staging, stage, dev, test, uat, beta, demo, legacy, debug.
- Internal and infrastructure: internal, intranet, vpn, backup, vault, nexus.
- Named internal tooling: jenkins, gitlab, grafana, kibana, jira, confluence, sonar.

Treat these as examples of the idea, a host whose name or content says it is
administrative, non-production, or internal, not a fixed list. A name in another language
or a novel tool name that means the same thing is the same class. Weigh the whole
response, a live host with such a name and a real application behind it, not a parked page
or a redirect to a public site.

## What Is Not A Finding

A production host that merely contains one of these words incidentally, or a name that
does not resolve or does not answer. The judgment is that a sensitive-by-nature surface is
actually live and reachable, not that a keyword appears.

## Evidence And PoC

Name what makes the surface interesting, the name fragment or the page, and cite the HTTP
status, title, and server. The PoC is a safe read, `curl -s <url>`, and a note of why the
surface warrants review or reduction.
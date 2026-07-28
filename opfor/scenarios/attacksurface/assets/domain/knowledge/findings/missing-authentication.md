---
title: Missing authentication on an exposed interface
impact: MEDIUM
tags: [cwe-306, owasp-a01]
clues:
- id: spring-actuator
  note: a Spring Boot Actuator index is present, an env or heapdump route may follow
  path: /actuator
  body_contains: _links
  content_type: json
- id: exposed-actuator-env
  note: a Spring Boot Actuator env dump is present, it leaks configuration secrets
  path: /actuator/env
  body_contains: propertysources
  content_type: json
- id: prometheus-metrics
  note: a Prometheus metrics page is present, it leaks internal detail
  path: /metrics
  body_contains: '# help'
- id: apache-server-status
  note: an Apache server-status page is present, it leaks live requests
  path: /server-status
  body_contains: apache server status
- id: directory-listing
  note: an autoindex directory listing is exposed, files under the path are enumerable
  body_regex: index of /|directory listing
---

# Missing Authentication On An Exposed Interface

An interface an operator can reach over HTTP without presenting a credential, that serves a
function or data a public visitor should not drive. This is the base observation of the mission,
that a subdomain answers, and the judgment is not whether it is reachable but whether reaching it
hands an attacker something, an internal or administrative action, a data read that is not a public
page, a management or debug surface, or an API that mutates state. Most reachable paths are meant to
be public, so this class is minted only when the exposed function is one a stranger should not have.

## Signals

- A live host or endpoint that answers with content, not a refusal, without any credential
  challenge. The capability marks a resource that already refused with a `401` or a `403` or an
  auth challenge, so what reaches this class is a resource that answered.
- A clue hit from the frontmatter, an Actuator index or env dump, a Prometheus metrics page, an
  Apache server-status page, or an autoindex directory listing, each a management or operational
  surface that should not face the internet unauthenticated.
- A host whose name or page identifies it as an administrative, non-production, or internal surface,
  admin, dashboard, portainer, phpmyadmin, adminer, gateway, staging, dev, test, or a named internal
  tool such as jenkins, gitlab, grafana, kibana. Read these as the idea of the shape, a host whose
  name or content says it is sensitive by nature, not a fixed list. The same meaning in another
  language or a novel tool name is the same signal.
- A host identified as a known open-source product's management or operational console, GitLab,
  Jenkins, Grafana, Kibana, Nacos, Consul, Harbor, a message-broker console, a database admin panel,
  reachable without authentication. The product identity comes from the `technologies/` fingerprints
  and the `guides/surfaces/` reasoning, this class judges only that the console answered unguarded.

## Severity Levers

Grade on the shared severity rubric, with reachability first. On top of the rubric, what the
interface grants sets the class-specific lever.

- A read-only login page for a product meant to face the internet, low.
- An administrative console, a non-production copy, or a metrics or debug surface, medium, since the
  surface is sensitive by nature even before a specific flaw is shown.
- A cluster, configuration, or management API, or a known product's admin console reachable with no
  credential, high.
- An unauthenticated read that returns secrets, configuration, or bulk personal data, critical.

## Positive And Negative Examples

- Positive. `GET /metrics` answers `200` with a body beginning `# HELP go_gc_duration_seconds`, a
  Prometheus page serving internal detail to anyone. Positive. A GitLab sign-in that also exposes
  `GET /-/metrics` or a project API answering without a session.
- Negative. `GET /admin` answers `302` to `accounts.google.com`, the interface is gated, not
  exposed, judge under improper-authentication. Negative. A marketing root that answers `200` with
  the same catch-all HTML for every path, the single-page-app shell, not a distinct exposed function.

## Not A Finding

- The shared false-positive traps settle the recurring look-alikes, a public-by-design page, a `401`
  or `403` refusal, a redirect to a sign-in flow, a refusing body, and a single-page-app catch-all
  shell. A finding survives only when the response is a distinct, sensitive function, not the host's
  baseline shell.
- A host correctly fronted by a per-request zero-trust proxy is gated, not exposed, judge it under
  improper-authentication.
- When a named CVE bears on the exposed surface, report known-vulnerability and let this exposure be
  the reachability context that class weighs, so one exposure is not reported twice.

## Evidence And PoC

Cite the status, the path, and what in the body shows a real sensitive interface rather than a shell
or a refusal. Name the product and version when the surface identifies them, so a later step can
check known vulnerabilities. The PoC is a safe read that demonstrates reachability, never an attack,
`curl -s <url>`, and a note that an operator should confirm whether the surface is meant to be
public. Do not log in or drive the interface.

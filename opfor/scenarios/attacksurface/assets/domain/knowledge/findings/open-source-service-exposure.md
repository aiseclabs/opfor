---
title: Open-source service exposure
impact: MEDIUM
triggers:
- gitlab
- jenkins
- grafana
- kibana
- nacos
- consul
- harbor
- rabbitmq
- phpmyadmin
- x-powered-by
---

# Open-Source Service Exposure

A reachable host can be a deployment of a known open-source product rather than the
target's own application, GitLab, Jenkins, Grafana, Kibana, Nacos, Consul, Harbor, a
message-broker console, a database admin panel, and so on. Identifying the product matters
because a known product has a known attack surface and a known history of vulnerabilities,
so an exposed instance is judged on what that product exposes, not on the path name alone.

## How To Identify The Product

Read the evidence, never guess from a host name. Product identity shows in the `server`
header, an `x-powered-by` or a product-specific header, the page title, a login page that
names the product, a version string in the body or a meta generator tag, and product-known
paths that answered. Name the product and, when the evidence shows it, the version, since
the version is what a later step matches against known vulnerabilities.

## What Rises To A Finding

Report an open-source service exposure when a management, administrative, or operational
interface of the product is reachable without authentication, or when a version is visible
that a later step should check against known vulnerabilities. Severity follows what the
interface grants. A read-only login page of a product meant to face the internet is low or
informational. An unauthenticated admin console, a metrics or debug surface, a cluster or
config API, or an instance whose visible version carries known critical vulnerabilities is
high.

## What Is Not A Finding

- A product login page that correctly enforces authentication, a gate is protection.
- A product genuinely meant to be public, judged by what it serves, not by being recognized.
- A host behind a zero-trust proxy, see that class, the service is not directly exposed.

## Evidence And PoC

Cite the header, title, version string, or product path that identifies the product, and
what shows the interface is reachable unauthenticated. Name the version when visible. A safe
read is `curl -s <url>`, never an attempt to log in or drive the product.
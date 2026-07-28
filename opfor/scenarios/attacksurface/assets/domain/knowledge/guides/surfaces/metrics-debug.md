---
title: Metrics and debug endpoints
kind: surface
detect:
  markers: ["/actuator", "# help", "server-status", propertysources, heapdump, "/debug/pprof", "go_gc_duration"]
---

# Metrics And Debug Endpoints

Operational surfaces a framework or server exposes for monitoring and diagnosis, a Spring Boot
Actuator tree, a Prometheus metrics page, an Apache server-status page, a Go pprof handler. They are
built for an internal network, not the internet, and they leak internal detail from live request
lines to full configuration, so an exposed one is a finding even before a specific secret is read.

## On The Recon Surface

- A Spring Boot Actuator index at `/actuator` with a `_links` JSON body, and the routes it links,
  above all `/actuator/env` with a `propertySources` body and `/actuator/heapdump`.
- A Prometheus page at `/metrics` whose body begins with `# HELP`, leaking internal metric detail.
- An Apache `/server-status` page listing live requests, or a Go `/debug/pprof` profiling handler.

## How To Read It

A metrics or debug surface exposed unauthenticated is medium by nature, since it is operational and
internal. It rises when the content itself is a secret, an Actuator `env` dump that carries
credentials or connection strings is a critical unauthenticated read of configuration. Grade by what
the body actually returns, not by the endpoint's name alone.

## Feeds

- `missing-authentication`, the operational surface reachable with no credential.
- `information-exposure`, when the body returns configuration or secrets rather than only metrics.

## Traps

A `/metrics` that answers `401` or `403` is gated. A public health check that returns only
`{"status":"UP"}` with no internal detail is not a leak, it is a liveness probe.

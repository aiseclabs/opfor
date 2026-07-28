---
cpe: prometheus:prometheus
markers:
  - prometheus time series collection
version: '"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"'
probe_paths:
  - /api/v1/status/buildinfo
---

# Prometheus

A metrics server whose web console answers on its own port. The root serves the title `Prometheus
Time Series Collection and Processing Server`, a distinctive string, and `/api/v1/status/buildinfo`
returns the exact `version` to an unauthenticated caller. This is the server itself, distinct from
the `/metrics` exposition a metrics-debug surface shows, which any instrumented app serves. An
exposed Prometheus is a browsable window onto every target it scrapes, its query API returning the
collected series, so it reads as a missing-authentication and an information-exposure case together.
Prometheus ships with no authentication of its own, so a reachable console is open by default rather
than by misconfiguration. No cassette is recorded yet, so coverage lists it as a gap.

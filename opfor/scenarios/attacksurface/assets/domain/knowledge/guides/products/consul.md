---
cpe: hashicorp:consul
markers:
  - "x-consul-index:"
  - "x-consul-knownleader:"
version: '"Version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"'
probe_paths:
  - /v1/agent/self
---

# Consul

A service-mesh and service-discovery agent whose HTTP API answers on its own port. Every API
response carries `X-Consul-Index` and `X-Consul-Knownleader` response headers, product-specific
headers no other service sends, so the marker survives a body that reveals nothing. Its `/v1/agent/
self` returns the agent configuration including the exact `Version`, though an ACL-enabled cluster
gates that path, in which case the header still identifies the product and the version is left
empty. An open agent exposes the service catalog and the key-value store, which routinely hold
internal topology and secrets, so it feeds an information exposure alongside the identification. No
cassette is recorded yet, so coverage lists it as a gap.

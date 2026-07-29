---
cpe: hashicorp:vault
markers:
  - vault-cluster-
version: '"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"'
probe_paths:
  - /v1/sys/health
---

# Vault

A secrets manager whose HTTP API answers on its own port. The `/v1/sys/health` endpoint is
unauthenticated by design, a load-balancer check, and returns a JSON carrying the cluster name
`vault-cluster-<id>` and the exact `version`, so `vault-cluster-` is a high-signal marker and the
version reads from the same reply. Identifying the product is not itself a finding, since the health
endpoint is meant to be reachable, but the running version drives the deterministic CVE report, and
any path beyond health that answers without a token is the real exposure the model judges. No
cassette is recorded yet, so coverage lists it as a gap.

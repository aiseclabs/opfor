---
markers:
  - "kbn-name:"
  - "kbn-version:"
version_paths:
  - /api/status
version: '"number"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"'
---

# Kibana

Verified against Kibana 8.15. It sets a `kbn-name` response header on every response including the
unauthenticated `/` that redirects to `/spaces/enter`, a high-signal marker. The `kbn-version`
response header was dropped in 8.x, so identification rides `kbn-name`, and the version comes from
`/api/status`, which returns it unauthenticated in `"version":{"number":"x.y.z"}` when the instance
is unsecured. A secured instance answers `/api/status` with 401, so it is still identified but
unversioned.

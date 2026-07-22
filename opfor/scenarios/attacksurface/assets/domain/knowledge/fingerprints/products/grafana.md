---
cpe: grafana:grafana
markers:
  - public/build/grafana
probe_paths:
  - /login
  - /api/health
version: '"database"\s*:\s*"ok"\s*,\s*"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"'
---

# Grafana

Verified against Grafana 10.4. The root redirects unauthenticated to `/login`, and the login page
serves the app-bundle path `public/build/grafana.<theme>.<hash>.css`, a string a page merely
mentioning Grafana does not carry, unlike the bare word. The version is not in the login page, but
`/api/health` returns it unauthenticated in a compact JSON, `{"database":"ok","version":"x.y.z"}`,
so that path is probed and the version read there.

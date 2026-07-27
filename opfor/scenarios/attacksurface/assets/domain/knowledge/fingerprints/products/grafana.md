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

## Reproductions

Grafana 8.0.0 through 8.3.0 carries CVE-2021-43798, an unauthenticated path traversal that reads an
arbitrary file through a plugin's public asset path. Its read-only reproduction recipe is not written
here, it is the vendored Nuclei template `knowledge/nuclei/CVE-2021-43798.yaml`, which opfor consumes
as data. The recipe grounds an accurate PoC only when the CVE lookup tied the CVE to the running
version, and the PoC is a read written for the operator to run, never sent to the target by this
reconnaissance run.

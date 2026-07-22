---
cpe: grafana:grafana
markers:
  - public/build/grafana
probe_paths:
  - /login
  - /api/health
version: '"database"\s*:\s*"ok"\s*,\s*"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"'
reproductions:
  - id: CVE-2021-43798
    method: GET
    path: "/public/plugins/mysql/../../../../../../../../etc/passwd"
    expect: "root:"
---

# Grafana

Verified against Grafana 10.4. The root redirects unauthenticated to `/login`, and the login page
serves the app-bundle path `public/build/grafana.<theme>.<hash>.css`, a string a page merely
mentioning Grafana does not carry, unlike the bare word. The version is not in the login page, but
`/api/health` returns it unauthenticated in a compact JSON, `{"database":"ok","version":"x.y.z"}`,
so that path is probed and the version read there.

## Reproductions

Grafana 8.0.0 through 8.3.0 carries CVE-2021-43798, an unauthenticated path traversal that reads an
arbitrary file through a plugin's public asset path. Its `reproductions` entry is the read-only GET
that demonstrates it and the `root:` marker its response bears when the instance reads back
`/etc/passwd`. The recipe is replayed only when the CVE lookup tied the CVE to the running version,
only under the intrusive EXPLOIT phase, and only as a read, and whether the marker actually returned
is the confirm judgment on the live receipt, not a match in code.

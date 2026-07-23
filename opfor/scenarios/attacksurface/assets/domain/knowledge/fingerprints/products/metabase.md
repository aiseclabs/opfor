---
cpe: metabase:metabase
markers:
  - metabasebootstrap
  - "metabase.device"
probe_paths:
  - /api/session/properties
version: '"tag"\s*:\s*"v?([0-9]+\.[0-9]+\.[0-9]+)"'
---

# Metabase

Verified against Metabase 0.40.4. The unauthenticated root serves the app shell, whose bootstrap
script carries the `metabaseBootstrap` identifier and whose response sets a `metabase.DEVICE`
cookie, two high-signal markers a page merely naming Metabase in prose does not carry. The version
is not in that shell, but `/api/session/properties` returns it unauthenticated in
`"version":{"tag":"vx.y.z"}`, so that path is probed and the version read there, the leading `v`
dropped so the value is the plain NVD version.

## Reproductions

Metabase before 0.40.5 carries CVE-2021-41277, an unauthenticated local file read through the
custom GeoJSON map loader, whose `url` parameter is loaded without validation so a `file://` URL
reads an arbitrary file. Its read-only reproduction is not written here, it is the vendored Nuclei
template `knowledge/nuclei/CVE-2021-41277.yaml`, which opfor consumes as data. The recipe fires only
for a CVE the lookup tied to the running version, only under the intrusive EXPLOIT phase, and only
as a read.

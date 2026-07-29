---
cpe: portainer:portainer
markers:
  - "<title>portainer</title>"
version: '"Version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"'
probe_paths:
  - /api/system/status
  - /api/status
---

# Portainer

A container-management console for Docker and Kubernetes, so a reachable instance is control over
the container hosts behind it, not merely a service banner. The app serves the title `Portainer`,
and its status endpoint returns the exact `Version`, at `/api/system/status` on current builds and
`/api/status` on older ones, both probed so the version is read wherever it lives. An
uninitialized instance answers the setup flow with no credential, which lets an unauthenticated
caller claim the admin account, so an exposed console feeds a missing or improper authentication
case with a high impact. No cassette is recorded yet, so coverage lists it as a gap.

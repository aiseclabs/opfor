---
cpe: konghq:kong
markers:
  - '"tagline":"welcome to kong"'
version: '"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"'
---

# Kong

An API gateway whose Admin API answers on its own port with a JSON root carrying `"tagline":
"Welcome to Kong"` and the exact `version`, a high-signal pair the proxy data plane does not emit.
The Admin API is meant to sit on a private interface, so reaching it from the outside is the
exposure itself, since it configures every route, upstream, and plugin the gateway runs. An open
Admin API therefore feeds a missing-authentication case at a high impact, a caller can add a route
that bypasses the gateway's own controls, and a version-matched vulnerability when the build is
known. No cassette is recorded yet, so coverage lists it as a gap.

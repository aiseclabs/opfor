---
kind: service
cpe: jenkins:jenkins
markers:
  - "x-jenkins:"
version: 'x-jenkins:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)'
---

# Jenkins

Verified against Jenkins 2.462.3. It sets an `X-Jenkins` response header carrying its version, on
every response including the unauthenticated `/` that returns 403, so the header is a high-signal
marker that also yields the exact version without an authenticated path.

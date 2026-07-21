---
product: Jenkins
cpe: jenkins:jenkins
markers:
  - "x-jenkins:"
version: 'x-jenkins:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)'
---

# Jenkins

Jenkins sets an `X-Jenkins` response header carrying its version, a high-signal marker that also
yields the exact version. Not yet verified against a captured real instance, add a cassette.

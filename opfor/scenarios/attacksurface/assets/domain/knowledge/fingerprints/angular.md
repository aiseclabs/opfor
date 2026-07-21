---
kind: framework
body:
  - "ng-version="
  - "_nghost-"
  - "_ngcontent-"
version: 'ng-version="([0-9]+\.[0-9]+\.[0-9]+)"'
---

# Angular

A front-end framework. Its root element carries an `ng-version="x.y.z"` attribute that also gives
the exact version, and its rendered DOM carries `_nghost-` and `_ngcontent-` markers. This is a
context tag on the host, not a finding and not a CVE lookup key, so the judge reads the role rather
than treating a framework version as a vulnerability.

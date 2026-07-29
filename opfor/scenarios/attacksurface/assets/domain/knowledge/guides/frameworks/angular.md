---
body:
  - "ng-version="
  - "_nghost-"
  - "_ngcontent-"
version: 'ng-version="([0-9]+\.[0-9]+\.[0-9]+)"'
bundle_version: 'angular v([0-9]+\.[0-9]+\.[0-9]+)'
npm: "@angular/core"
---

# Angular

A front-end framework. Its root element carries an `ng-version="x.y.z"` attribute that also gives
the exact version, and its rendered DOM carries `_nghost-` and `_ngcontent-` markers. Its core is
published on npm as `@angular/core`, and its known vulnerabilities are catalogued in the ecosystem
advisory database, so when no product is identified this framework and the version `ng-version`
gives become the CVE-lookup subject and yield version-matched known vulnerabilities. The judge still
reads the role, whether the exposed surface is reachable, rather than treating the catalogued CVE as
the whole story.

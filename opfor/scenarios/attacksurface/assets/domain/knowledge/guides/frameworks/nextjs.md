---
body:
  - 'id="__next"'
  - "/_next/static/"
  - "__next_data__"
headers:
  - "x-powered-by: next.js"
npm: "next"
---

# Next.js

A React meta-framework. Its pages carry the `__next` root element, the `/_next/static/` asset
prefix, and a `__NEXT_DATA__` script, and it sometimes sets an `x-powered-by: Next.js` header. Its
core is published on npm as `next`, so when no product is identified it becomes the CVE-lookup
subject, queried against the ecosystem advisory database. A Next.js page also carries React's own
markers, so it and React can both match, and Next.js is listed first and owns the subject as the
meta-framework the host actually runs. It publishes no version plainly, a build id or chunk hash is
never read as one, so unless a versioned asset url reveals it the lookup matches the package across
its whole history and reports one low unconfirmed lead, the running version to establish before
acting, rather than a version-matched finding.

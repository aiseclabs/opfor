---
body:
  - 'id="__next"'
  - "/_next/static/"
  - "__next_data__"
headers:
  - "x-powered-by: next.js"
---

# Next.js

A React meta-framework. Its pages carry the `__next` root element, the `/_next/static/` asset
prefix, and a `__NEXT_DATA__` script, and it sometimes sets an `x-powered-by: Next.js` header. This
is a context tag on the host, what the site is built on, not a finding and not a CVE lookup key, so
the judge reads the role rather than treating it as a vulnerability. Next.js publishes no version
plainly, so none is claimed, a build id or chunk hash is never read as one.

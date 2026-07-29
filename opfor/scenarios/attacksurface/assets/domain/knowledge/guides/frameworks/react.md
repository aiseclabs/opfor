---
body:
  - "data-reactroot"
  - "<!--$-->"
---

# React

A front-end library. A server-rendered React tree marks its root with `data-reactroot` on older
versions, and a streaming React 18 page leaves `<!--$-->` hydration-boundary comments around its
suspense boundaries. This is a context tag on the host, what the site is built on, not a finding and
not a CVE lookup key, so the judge reads the role rather than treating the library as a
vulnerability. React publishes no version plainly, so none is claimed. A purely client-side React
app that ships an empty mount point and a bundle often leaves no server-visible marker at all, so an
unidentified host is not evidence React is absent, and the more common server-rendered case is a
Next.js app identified by its own guide.

---
body:
  - "data-reactroot"
  - "<!--$-->"
npm: "react"
---

# React

A front-end library. A server-rendered React tree marks its root with `data-reactroot` on older
versions, and a streaming React 18 page leaves `<!--$-->` hydration-boundary comments around its
suspense boundaries. Its core is published on npm as `react`, and its known vulnerabilities live in
the GitHub Advisory Database rather than the NVD product catalogue, so it carries that npm name and,
when no product is identified, becomes the CVE-lookup subject queried against the ecosystem advisory
database. React core carries few advisories, and that is a fact of the record, not a blind spot: the
lookup runs and reports what the database holds. Its server-render markers overlap the Next.js
meta-framework that carries them, so a server-rendered page is more often identified as Next.js by
its own guide, which is listed first and owns the subject. React publishes no version plainly, so
where a versioned CDN asset gives one it is read, else the lookup matches the package across its
whole history.

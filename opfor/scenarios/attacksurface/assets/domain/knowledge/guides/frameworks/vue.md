---
body:
  - "data-v-"
  - "data-server-rendered"
npm: "vue"
---

# Vue

A front-end framework. Its single-file components render elements carrying a scoped
`data-v-<hash>` attribute, and a server-rendered page marks its mount root with
`data-server-rendered`. Its core is published on npm as `vue`, and its known vulnerabilities live in
the GitHub Advisory Database rather than the NVD product catalogue, so it carries that npm name and,
when no product is identified, becomes the CVE-lookup subject queried against the ecosystem advisory
database. That NVD indexes no core Vue product does not mean Vue is free of vulnerabilities, only
that they are catalogued in the ecosystem database this lookup reads. Vue publishes no version
plainly in a production build, so where a page loads Vue from a versioned CDN asset that version is
read and the lookup is version-matched, else it matches the package across its whole history and
reports one low unconfirmed lead. A pure client-side app that ships an empty mount point may not
identify at all.

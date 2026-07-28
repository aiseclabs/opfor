# Frameworks

One file per front-end framework detected as a context tag. Each carries only body and header
markers, no `cpe` and no version, since a framework names what a site is built on and is never a CVE
lookup key, so the judge reads the role rather than treating it as a vulnerability, invariant 1.

Covered frameworks: `angular`, `nextjs`.

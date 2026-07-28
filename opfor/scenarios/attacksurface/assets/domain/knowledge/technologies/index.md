# Technologies

The per-technology knowledge the identify and enrich steps read to name what a host runs, kept as
data so adding a product or a framework is a data change, not a code change, invariant 1. Split by
how the knowledge is used downstream.

- `products/` Open-source products identified by markers, each carrying a `cpe` and a version
  pattern that drive the CVE lookup.
- `frameworks/` Front-end frameworks detected as context tags, no version and no CVE lookup, read by
  the judge to know what a site is built on.

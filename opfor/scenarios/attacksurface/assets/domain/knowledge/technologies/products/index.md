# Products

One file per open-source product the fingerprint step can identify. Each carries the markers that
name the product, a `cpe` that drives the CVE lookup, and a version pattern with the paths where the
version is read, so adding a product is one file, not a code change, invariant 1. The body is
verified against a named release. A product file may also carry a `reproductions` frontmatter list
to ground a PoC from the product's own knowledge, an extension seam no product uses today, the
reproduction recipes in use are the vendored templates under `nuclei/`.

Covered products: `airflow`, `elasticsearch`, `gitlab`, `grafana`, `jenkins`, `kibana`, `metabase`,
`sonarqube`.

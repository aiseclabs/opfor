---
scenario: websurface
targets:
  - id: example
    kind: org
  - id: example.com
    kind: domain
    host: example.com
    is_root: true
---
# Example full web-surface scan

The whole two-level fanout in one campaign: from a confirmed root domain to its
subdomains and live services (asset fanout), then from each service to its
endpoints (interface fanout), then per-endpoint vulnerability tests.

`opfor run campaigns/fullscan-example` drives the `websurface` scenario:

```
org    -> candidate roots   (passive, reported as candidates only)
domain -> subdomains        (certificate transparency, passive DNS, cert pivot)
service -> endpoints        (OpenAPI/Swagger, archives, JavaScript bundles)
endpoint -> vulnerabilities (templated checks; intrusive fuzzing is tier-gated)
```

The `org` seed is a keyword the discovery step uses to look for candidate root
domains passively. Discovered roots are reported as candidates only, they are not
expanded until you confirm them by adding them here as a `kind: domain` entry and
listing the suffix in `scope.yaml`. The tool never asserts a candidate is yours.

The `domain` seeds are roots you have already confirmed you are authorized to
assess. Replace these with your own.

`scope.yaml` caps this run at probe tier, so it stops at the endpoint map plus
safe templated checks. Raise `max_tier` to `intrusive` only against a target you
are authorized to actively fuzz, and the same one command then runs the whole
domain -> endpoints -> vulns chain.

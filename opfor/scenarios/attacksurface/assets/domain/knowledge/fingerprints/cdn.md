---
kind: fronting
category: cdn
cnames:
  - cloudflare.net
  - cloudfront.net
  - fastly.net
  - fastlylb.net
  - edgekey.net
  - edgesuite.net
  - akamaiedge.net
  - akamai.net
  - akamaized.net
  - llnwd.net
  - cachefly.net
  - b-cdn.net
  - azureedge.net
  - azurefd.net
servers:
  - cloudflare
  - akamaighost
  - varnish
headers:
  - cf-ray
  - x-amz-cf-id
  - x-fastly-request-id
  - x-akamai-transformed
  - x-cache
---

# CDN

A content-delivery / edge network sits in front of the origin. When a host is fronted by a CDN the server it answers from is the edge, not the org's own machine, so the judge reads a finding here as describing the edge, not the origin.

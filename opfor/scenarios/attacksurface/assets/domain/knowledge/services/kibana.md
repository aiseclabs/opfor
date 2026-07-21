---
vendor: elastic
product: kibana
markers:
  - "kbn-version:"
  - "kbn-name:"
version: 'kbn-version:\s*([0-9]+\.[0-9]+\.[0-9]+)'
---

# Kibana

Kibana sets `kbn-version` and `kbn-name` response headers, the version header giving the exact
version. Not yet verified against a captured real instance, add a cassette.

---
cpe: elastic:elasticsearch
markers:
  - "you know, for search"
  - lucene_version
version: '"number"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"'
---

# Elasticsearch

Verified against Elasticsearch 8.15. The unauthenticated root JSON carries the tagline "you know,
for search" and a `lucene_version` field, and the version in `"number":"x.y.z"`, all high-signal.
This is the classic unsecured exposure. A secured instance answers the root with 401 and leaks
none of it, so it is not fingerprinted this way, which is correct, a locked instance is not
identifying itself.

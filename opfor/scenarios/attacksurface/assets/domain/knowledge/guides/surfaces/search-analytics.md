---
title: Search and index engines
kind: surface
detect:
  markers: [elasticsearch, kibana, opensearch, solr, "cluster_name", "/_cat/indices", "/_search", "number_of_shards"]
---

# Search And Index Engines

A search or indexing engine, Elasticsearch, OpenSearch, Solr, and their consoles such as Kibana.
They routinely hold a copy of an application's data, logs, and events, and their default HTTP API is
unauthenticated, so an exposed cluster is a bulk data read, not merely a service banner.

## On The Recon Surface

- An Elasticsearch or OpenSearch root that answers with a `cluster_name` and a version JSON, or a
  `/_cat/indices` listing the indices and their document counts.
- A `/_search` endpoint that returns documents to an unauthenticated query, the data itself.
- A Kibana console reachable without a credential, a browsable window onto the indices behind it.

## How To Read It

An index root that answers unauthenticated is at least a missing-authentication finding, and a
`/_search` or `/_cat/indices` that returns data or index names is a bulk information exposure, graded
by what the documents are, which is often personal or operational data. A Kibana console open to the
internet inherits the severity of the cluster it fronts. Name the product and version.

## Feeds

- `missing-authentication`, an engine or console reachable with no credential.
- `information-exposure`, a `/_search` or `/_cat` reply that returns documents or index names.
- `known-vulnerability`, an engine or console at a version with a known flaw.

## Traps

A public site search box that proxies queries through the application is not the engine's own open
API. A cluster that answers `401` on `/_cat/indices` is gated.

---
title: Source code exposure
impact: MEDIUM
triggers:
  - source map
---

# Source Code Exposure

A reachable JavaScript source map, `bundle.js.map`, that a build tool shipped to production
and left public. A source map hands back the application's original code, so it is judged
on how much it gives away.

## What Rises To A Finding

- A source map that inlines the original source in `sourcesContent`. The front-end source
  is reconstructable, comments, internal API routes, feature flags, and now and then a
  hardcoded secret. Medium, and higher when the recovered source names an internal host, an
  unreleased feature, or a credential, which the operator should then read for directly.
- A source map that lists original source paths without the content. It still leaks the
  internal module and directory structure, useful for mapping the app. Low.

## What Is Not A Finding

- No reachable map, the bundles ship none, which is the expected production posture.
- A map for a third-party open-source library rather than the application's own code. The
  source is already public, so it exposes nothing. Judge by whether the sources are the
  target's own.

## Evidence And PoC

Cite the map url, whether it inlines source, the count of sources, and a sample of the
source paths. A safe read is `curl -s <map url>`, and a note that the source can be
reconstructed with a source-map tool, never anything beyond the read.

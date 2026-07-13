---
title: Exposed cloud storage bucket
impact: HIGH
triggers:
  - cloud bucket
  - cloud storage
  - listable
---

# Exposed Cloud Storage Bucket

A cloud object-storage bucket, an S3, GCS, or Azure Blob container, that exists under a name
derived from the target and answers an anonymous request. A bucket named for the org or one
of its domains that lists its objects to the public is high value, since it often holds
backups, database dumps, logs, or user uploads the target never meant to expose.

## What Rises To A Finding

- A listable bucket attributable to the target. The anonymous list returned an object
  listing, so anyone can read the index and then the objects. High, and critical when the
  name and the objects clearly tie it to production data, a backup, or a dump. Judge
  ownership on the name, a bucket named for the brand or an in-scope domain is the target's,
  a generic word alone is not.

## What Is Not A Finding

- A bucket whose name matches a common word but nothing ties it to the target, a namesake
  someone else owns. Say the name is unattributed rather than claiming it.
- A bucket that exists but refused the list, a `private` state, is at most an informational
  note that the name is taken, not an exposure, since no object was reachable.
- A name that did not resolve to any bucket.

## Evidence And PoC

Name the bucket, the provider, and the state, listable or private. The PoC is a safe read,
`curl -s <the list url>`, the exact anonymous request that returned the listing, and a note
that an operator should review the objects for sensitive data, never a write or a delete.

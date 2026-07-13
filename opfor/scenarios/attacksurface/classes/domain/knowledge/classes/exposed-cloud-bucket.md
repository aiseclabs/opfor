---
title: Exposed cloud storage bucket
impact: HIGH
triggers:
  - cloud bucket
  - cloud storage
  - listable
---

# Exposed Cloud Storage Bucket

A cloud object-storage bucket, an S3, GCS, or Azure Blob container, that the target reveals
and that answers an anonymous request. The bucket is discovered from evidence, a url the
target's own pages load or a subdomain CNAME that points at it, so it is the target's, and
that evidence is shown as `referenced by <host>` or `CNAME from <host>`. A bucket that lists
its objects to the public is high value, since it often holds backups, database dumps, logs,
or user uploads the target never meant to expose.

## What Rises To A Finding

- A listable bucket. The anonymous list returned an object listing, so anyone can read the
  index and then the objects. High, and critical when the bucket or its objects clearly hold
  production data, a backup, or a dump. Ownership is not in question here, the target's own
  page or DNS pointed at it, so judge on what the listing exposes.

## What Is Not A Finding

- A bucket that exists but refused the list, a `private` state. It is at most an
  informational note that the bucket is in use, not an exposure, since no object was
  reachable anonymously.
- A reference that did not resolve to a reachable bucket.

## Evidence And PoC

Name the bucket, the provider, the state, and the evidence that ties it to the target. The
PoC is a safe read, `curl -s <the list url>`, the exact anonymous request that returned the
listing, and a note that an operator should review the objects for sensitive data, never a
write or a delete.

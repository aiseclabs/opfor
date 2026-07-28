---
title: Object storage buckets
kind: surface
detect:
  markers: [nosuchbucket, "the specified bucket", "s3.amazonaws.com", listbucketresult, "blob.core.windows.net", "storage.googleapis.com", "accessdenied"]
---

# Object Storage Buckets

A cloud object store, an S3 bucket, a Google Cloud Storage bucket, an Azure blob container, that a
subdomain fronts or a page references. Two distinct risks live here, an open bucket that lists or
serves its objects to anyone, and a dangling bucket a name still points at after the bucket was
deleted, which anyone can re-register.

## On The Recon Surface

- A subdomain whose CNAME or content points at `s3.amazonaws.com`, `storage.googleapis.com`, or
  `blob.core.windows.net`.
- A `ListBucketResult` XML body, an open bucket serving its object index, versus an `AccessDenied`
  body, a bucket that exists but refuses listing.
- A `NoSuchBucket` or `the specified bucket does not exist` body, a released bucket the name still
  delegates to, a takeover candidate.

## How To Read It

An open bucket that lists or serves objects unauthenticated is a data exposure, graded by what the
objects are. A `NoSuchBucket` under a live subdomain is a takeover, the provider re-issues the name
on a first-come basis. An `AccessDenied` bucket is gated, note it, do not grade it as open.

## Feeds

- `missing-authentication`, an open bucket listing or serving objects with no credential.
- `subdomain-takeover`, a dangling name pointing at a released bucket.
- `information-exposure`, when the listed or served objects are themselves sensitive.

## Traps

`AccessDenied` means the bucket exists and refuses you, it is not open and it is not takeable. A
bucket the operator intends to serve public assets from is public by design, not a finding.

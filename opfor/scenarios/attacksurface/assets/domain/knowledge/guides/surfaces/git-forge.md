---
title: Git forges and repositories
kind: surface
detect:
  markers: [gitlab, gitea, gogs, "/.git/", "index of /.git", bitbucket, "gitlab_session", "gitweb"]
---

# Git Forges And Repositories

A source-hosting product, GitLab, Gitea, Gogs, or a bare `.git` directory a web server exposes. The
recon value is high, a forge often carries private code, credentials in history, and CI
configuration, and an exposed `.git` directory lets an attacker reconstruct the working tree
offline.

## On The Recon Surface

- A GitLab, Gitea, or Gogs sign-in or project page, identified by its branding, a session cookie
  such as `_gitlab_session`, or a version string.
- A web-served `.git/` directory, an `index of /.git` listing or a readable `/.git/config` or
  `/.git/HEAD`, which exposes the repository contents.
- A public project listing or an API that answers without a session, exposing repository names and
  sometimes their contents.

## How To Read It

An exposed `.git` directory is a high-value read, the config and packed objects reconstruct the
code, grade it by what the repository holds. A forge console reachable unauthenticated is a
missing-authentication finding, and its version drives a CVE lookup, forges carry a long history of
pre-auth flaws. Name the product and version.

## Feeds

- `missing-authentication`, a forge console or a repository reachable with no credential.
- `information-exposure`, a served `.git` directory or a project listing that leaks code or names.
- `known-vulnerability`, a forge at a version with a known flaw.

## Traps

A public open-source project the operator intends to host is public by design. A `/.git/` path that
answers `403` or `404` is not exposed.

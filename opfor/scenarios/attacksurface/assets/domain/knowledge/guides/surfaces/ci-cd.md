---
title: CI and CD systems
kind: surface
detect:
  markers: [jenkins, hudson, "x-jenkins", argo, drone, teamcity, "/job/", "build #", concourse]
---

# CI And CD Systems

A build and deployment system, Jenkins, Argo CD, Drone, TeamCity, Concourse. These sit at the center
of a delivery pipeline, they hold deployment credentials and can run arbitrary build steps, so an
exposed one is among the highest-value recon findings, a foothold into the software supply chain.

## On The Recon Surface

- A Jenkins dashboard, identified by an `X-Jenkins` header, a `/job/` path, or its branding, and its
  script console or build history.
- An Argo CD, Drone, TeamCity, or Concourse UI reachable without a credential, listing pipelines or
  build logs.
- A build log or artifact endpoint that answers unauthenticated, often leaking secrets printed
  during a build.

## How To Read It

A CI or CD console reachable unauthenticated is high by nature, it grants pipeline visibility and
often build execution. It is critical when an unauthenticated action can run a build or read
deployment credentials. Name the product and version, these systems carry frequent pre-auth
remote-code-execution CVEs, so a version turns the exposure into a known-vulnerability lead.

## Feeds

- `missing-authentication`, a CI or CD console or API reachable with no credential.
- `known-vulnerability`, a build system at a version with a known flaw.
- `information-exposure`, a build log or artifact that leaks a secret.

## Traps

A public status badge or a read-only build-status page a project intends to publish is not the
console. A console that redirects to a sign-in is gated.

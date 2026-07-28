---
title: Administrative consoles
kind: surface
detect:
  markers: [admin, dashboard, portainer, phpmyadmin, adminer, "control panel", "sign in", wp-admin]
---

# Administrative Consoles

A management interface a product ships for operators, a database admin panel, a container or cluster
dashboard, a CMS back office. Its whole purpose is privileged action, so it is sensitive by nature,
and the recon question is not what it can do but whether it answers without a credential.

## On The Recon Surface

- A host whose name or page identifies a management role, `admin`, `dashboard`, `portainer`,
  `phpmyadmin`, `adminer`, `wp-admin`, a Kubernetes or container dashboard. Read these as the shape,
  a novel tool name with the same meaning is the same signal.
- A console that renders its own UI on a `200` rather than redirecting to a sign-in, a strong sign
  it is reachable unauthenticated.
- A named product console whose version is readable, which turns a reachable console into a
  known-vulnerability lead.

## How To Read It

A login page for a console meant to face the internet is low, it is gated. A console that renders
its operational UI without a credential is medium at least, and one that exposes a cluster,
configuration, or data-management action unauthenticated is high. Name the product and version when
the page shows them, so a CVE lookup can follow.

## Feeds

- `missing-authentication`, a console reachable with no credential, graded by what it grants.
- `known-vulnerability`, a named console at a version with a known flaw.
- `improper-authentication`, a console behind a gate that a sub-route bypasses.

## Traps

A console that redirects to a sign-in or answers `401` is gated, not exposed. A public status or
documentation page that merely has `admin` in its URL is not a management interface.

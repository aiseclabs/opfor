---
scenario: recon
targets:
  - id: example
    kind: org
  - id: example.com
    kind: domain
    host: example.com
    is_root: true
---
# Example attack-surface recon

A template recon campaign. The `org` seed is a keyword the discovery step uses to
look for candidate root domains, passively. Discovered roots are reported as
candidates only, they are not expanded until you confirm them by adding them here
as a `kind: domain` entry and listing the suffix in `scope.yaml`. The tool never
asserts that a candidate belongs to you, you confirm it.

The `domain` seeds are the roots you have already confirmed you are authorized to
assess. Replace these with your own.

This is passive plus light recon only: certificate transparency and DNS are recon
tier, a single HTTP read of each domain root is probe tier. Nothing intrusive.

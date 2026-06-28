---
scenario: recon
targets:
  - id: example.com
    kind: domain
    host: example.com
    is_root: true
---
# Example attack-surface recon

A template recon campaign. Replace the seed roots below with the domains you are
authorized to assess, one `kind: domain` entry per owned root, and set the
matching suffixes in `scope.yaml`. The engine takes whatever seed you give it and
expands from there, it has no built-in target.

This is passive plus light recon only: certificate-transparency lookups (recon
tier) and a single HTTP read of each domain root (probe tier). No paths are
fuzzed, no inputs are sent, nothing intrusive. Scope is locked to the authorized
domains, so nothing outside the estate is ever touched.

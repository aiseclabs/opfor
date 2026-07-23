---
cpe: apache:druid
markers:
  - unified-console.html
  - org.apache.druid
probe_paths:
  - /status
version: '"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"'
---

# Apache Druid

Verified against Apache Druid 0.20.0. The unauthenticated router root redirects to
`unified-console.html`, the Druid web console, a redirect target a page merely mentioning Druid does
not carry. The unauthenticated `/status` endpoint returns a JSON document whose module list names
`org.apache.druid` and whose top-level `version` field carries the exact version, so the version is
read there without a login.

## Reproductions

Apache Druid before 0.20.1 carries CVE-2021-25646, an unauthenticated remote code execution. A crafted
sampler task enables JavaScript per request even when the server disables it globally, so a POST to
`/druid/indexer/v1/sampler` runs code and, in the published proof, reads a file. The reproduction is
not written here, it is the vendored Nuclei template `knowledge/nuclei/CVE-2021-25646.yaml`, which
opfor consumes as data. It is a state-changing method, so it grounds a recipe that fires only when the
CVE lookup ties the CVE to the running version, only under the exploit tier with the explicit
authorization, and its benign proof is an `/etc/passwd` line the response returns. Whether it actually
fired is the confirm judge's ruling on the live receipt, not a match in code.

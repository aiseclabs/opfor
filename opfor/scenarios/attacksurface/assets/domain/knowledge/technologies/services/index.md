# Service Fingerprints

Each file here is one open-source service the scan identifies without a model call, at
`technologies/services/<name>.md`. The identify seam tries this table first and falls to the model
on a miss, so a thin or stale table identifies less rather than wrong. A file carries YAML
frontmatter for the mechanics and a prose body that records how the markers were verified.

Frontmatter fields:

- `cpe`, required, the NVD `vendor:product` key the CVE lookup queries. A file without a `cpe` is
  skipped, so a service that carries no lookup key is not a half-defined unit.
- `markers`, required, the substrings that identify the product. Any one appearing in the host
  evidence names the service. A file without markers is skipped. Keep markers specific to a running
  instance, an asset-bundle path or a product header, not a bare product word a prose page carries,
  or a page merely mentioning the product fingerprints as running it.
- `version`, optional, a regex whose first group is the version, read from the evidence. A malformed
  pattern fails the run loudly here rather than skipping the service mid-scan.
- `probe_paths`, optional, extra paths the endpoint probe fetches so a version an endpoint carries,
  such as `/api/health`, reaches the evidence the version regex reads.

The title, the `# Name` heading, is the human name reported.

Adding a service is a new file here, never an engine or capability change. Each service is
backtested by a recorded cassette under `evals/corpus/<slug>/`, its markers and version scored
against a real instance, so a fingerprint that stops matching is a caught regression.

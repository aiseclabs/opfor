# Vendored Nuclei Templates

Read-only, vendored snapshots of Nuclei community templates, consumed by opfor as a data source,
not run through the Nuclei binary. opfor reads a template as knowledge, invariant 1, and drives its
requests with its own capabilities and scope, so the template supplies the shape of a check while
opfor decides the target and judges the result. See `assets/domain/nuclei.py` for the consumer.

Vendoring rather than fetching at scan time keeps a run reproducible and offline, and it survives
upstream going away, we keep what we synced and can maintain our own subset. Only the tractable
subset is consumed, the http protocol with status, word, and regex matchers. A template using
anything else is reported unsupported, a visible coverage gap, never silently half-loaded.

Source: `projectdiscovery/nuclei-templates`, MIT licensed. Each file keeps its upstream `id` and its
original path is recorded below, so a sync is a diff against the same upstream file.

- `CVE-2021-43798.yaml`, upstream `http/cves/2021/CVE-2021-43798.yaml`, Grafana arbitrary file read.
- `CVE-2021-41277.yaml`, upstream `http/cves/2021/CVE-2021-41277.yaml`, Metabase GeoJSON local file read.

To sync: refresh a file from the same upstream path, re-run the eval that verifies it against a live
instance, and only then commit the update.

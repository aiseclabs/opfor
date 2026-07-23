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
- `CVE-2019-6340.yaml`, upstream `http/cves/2019/CVE-2019-6340.yaml`, Drupal REST deserialization command run. A state-changing POST recipe, replayed only at the exploit tier, whose benign `id` proof rides in the response.
- `CVE-2023-38646.yaml`, upstream `http/cves/2023/CVE-2023-38646.yaml`, Metabase H2 pre-auth command execution. A multi-step chain, it reads the setup token from one response and spends it in the next, driven whole at the exploit tier, its dsl matcher consumed by `nuclei_chain`.

To sync: refresh a file from the same upstream path, re-run the eval that verifies it against a live
instance, and only then commit the update.

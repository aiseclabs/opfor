"""Domain-class sources facade, re-exporting the dns, http, tls, ports, passive, parsers,
javascript, fingerprint, and storage modules.

Resolution, the shared network constants, and address filtering live in `dns`, HTTP transport
in `http`, the TLS posture in `tls`, the port scan in `ports`, passive OSINT source clients in
`passive`, body and document parsers in `parsers`, JavaScript extraction in `javascript`,
deterministic product fingerprinting in `fingerprint`, and cloud object-storage URL parsing in
`storage`. This module gathers the public names in one
place so a caller keeps a single import. It re-exports public names only, a caller that needs
a module's private detail imports it from the owning module, so the facade does not turn
implementation into public API.
"""

from __future__ import annotations

from opfor.scenarios.attacksurface.assets.domain.sources.dns import (
    dns_email_posture,
    resolve_host,
)
from opfor.scenarios.attacksurface.assets.domain.sources.http import (
    fetch_document,
    fetch_public_url,
    fetch_readonly,
    fetch_url,
    graphql_introspect,
    http_probe,
)
from opfor.scenarios.attacksurface.assets.domain.sources.fingerprint import (
    fingerprint,
    load_services,
    service_probe_paths,
)
from opfor.scenarios.attacksurface.assets.domain.sources.tls import tls_probe
from opfor.scenarios.attacksurface.assets.domain.sources.passive import (
    Enumeration,
    certspotter_subdomains,
    cves_from_nvd,
    dnsdumpster_subdomains,
    hosts_from_file,
    nvd_cves,
    otx_subdomains,
    roots_from_file,
    subdomains,
    subdomains_from_dnsdumpster,
    subdomains_from_otx,
    subdomains_from_vt,
    virustotal_subdomains,
    wayback_paths,
)
from opfor.scenarios.attacksurface.assets.domain.sources.parsers import (
    backup_candidates,
    info_from_openapi,
    operations_from_introspection,
    paths_from_openapi,
    robots_entries,
    same_host_path,
    sitemap_paths,
    split_operation,
)
from opfor.scenarios.attacksurface.assets.domain.sources.javascript import (
    paths_in_javascript,
    script_sources,
    secrets_in_text,
    source_map_from_text,
    urls_in_javascript,
)
from opfor.scenarios.attacksurface.assets.domain.sources.storage import (
    bucket_listable,
    cloud_bucket_from_url,
    cloud_refs_in_text,
)


# The public source names this facade re-exports, declared so the public surface is explicit
# and a name that stops being used through the facade is caught rather than lingering.
__all__ = [
    "Enumeration",
    "backup_candidates",
    "bucket_listable",
    "certspotter_subdomains",
    "cloud_bucket_from_url",
    "cloud_refs_in_text",
    "cves_from_nvd",
    "dns_email_posture",
    "dnsdumpster_subdomains",
    "fetch_document",
    "fetch_public_url",
    "fetch_readonly",
    "fetch_url",
    "fingerprint",
    "graphql_introspect",
    "hosts_from_file",
    "http_probe",
    "info_from_openapi",
    "load_services",
    "service_probe_paths",
    "nvd_cves",
    "operations_from_introspection",
    "otx_subdomains",
    "paths_from_openapi",
    "paths_in_javascript",
    "resolve_host",
    "robots_entries",
    "roots_from_file",
    "same_host_path",
    "script_sources",
    "secrets_in_text",
    "sitemap_paths",
    "source_map_from_text",
    "split_operation",
    "subdomains",
    "subdomains_from_dnsdumpster",
    "subdomains_from_otx",
    "subdomains_from_vt",
    "tls_probe",
    "urls_in_javascript",
    "virustotal_subdomains",
    "wayback_paths",
]

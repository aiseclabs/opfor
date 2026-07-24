"""Domain-class sources facade, re-exporting the dns, http, tls, enumeration, nvd, seeds, parsers,
javascript, and storage modules. These are the external-data adapters and low-level parsers a
capability acts through. Identification logic that reads the knowledge tables, the service
fingerprint and the framework and provider classifiers, lives one level up in
`domain/fingerprint.py` and `domain/classifiers.py`, not here.

Resolution, the shared network constants, and address filtering live in `dns`, HTTP transport in
`http`, the TLS posture in `tls`, passive subdomain and path enumeration in `enumeration`, the NVD
CVE lookup in `nvd`, the operator seed-file loaders in `seeds`, body and document parsers in
`parsers`, JavaScript extraction in `javascript`, and cloud object-storage URL parsing in
`storage`. This module gathers the public names in one place so a caller keeps a single import. It
re-exports public names only, a caller that needs a module's private detail imports it from the
owning module, so the facade does not turn implementation into public API.
"""

from __future__ import annotations

from opfor.scenarios.attacksurface.assets.domain.sources.dns import resolve_host
from opfor.scenarios.attacksurface.assets.domain.sources.http import (
    chain_fetch,
    fetch_document,
    fetch_exploit,
    fetch_readonly,
    fetch_url,
    graphql_introspect,
    http_probe,
)
from opfor.scenarios.attacksurface.assets.domain.sources.enumeration import (
    Enumeration,
    certspotter_subdomains,
    dnsdumpster_subdomains,
    otx_subdomains,
    subdomains,
    subdomains_from_dnsdumpster,
    subdomains_from_otx,
    subdomains_from_vt,
    virustotal_subdomains,
    wayback_paths,
)
from opfor.scenarios.attacksurface.assets.domain.sources.nvd import (
    cves_from_nvd,
    nvd_cves,
)
from opfor.scenarios.attacksurface.assets.domain.sources.seeds import (
    hosts_from_file,
    roots_from_file,
)
from opfor.scenarios.attacksurface.assets.domain.sources.parsers import (
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
    urls_in_javascript,
)
from opfor.scenarios.attacksurface.assets.domain.sources.observations import (
    Liveness,
    Resolution,
    Response,
)


# The public source names this facade re-exports, declared so the public surface is explicit
# and a name that stops being used through the facade is caught rather than lingering.
__all__ = [
    "Enumeration",
    "Liveness",
    "Resolution",
    "Response",
    "certspotter_subdomains",
    "cves_from_nvd",
    "dnsdumpster_subdomains",
    "chain_fetch",
    "fetch_document",
    "fetch_exploit",
    "fetch_readonly",
    "fetch_url",
    "graphql_introspect",
    "hosts_from_file",
    "http_probe",
    "info_from_openapi",
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
    "sitemap_paths",
    "split_operation",
    "subdomains",
    "subdomains_from_dnsdumpster",
    "subdomains_from_otx",
    "subdomains_from_vt",
    "urls_in_javascript",
    "virustotal_subdomains",
    "wayback_paths",
]

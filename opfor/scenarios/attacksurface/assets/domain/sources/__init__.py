"""Domain-class sources facade, re-exporting the dns, http, enumeration, nvd, osv, seeds, parsers,
javascript, and observations modules. These are the external-data adapters and low-level parsers a
capability acts through. Identification logic that reads the knowledge tables, the service
fingerprint and the framework and provider classifiers, lives one level up in
`domain/fingerprint.py` and `domain/classifiers.py`, not here.

Resolution, the shared network constants, and address filtering live in `dns`, HTTP transport in
`http`, passive subdomain and path enumeration in `enumeration`, the NVD CVE lookup in `nvd`, the
ecosystem CVE lookup in `osv`, the operator seed-file loaders in `seeds`, body and document parsers in `parsers`, JavaScript
extraction in `javascript`, and the typed source observations in `observations`. The per-source
API keys live in `keys`, read there by the adapters that use them. This module gathers the public
names in one place so a caller keeps a single import. It re-exports public names only, a caller
that needs a module's private detail imports it from the owning module, so the facade does not turn
implementation into public API.
"""

from __future__ import annotations

from opfor.scenarios.attacksurface.assets.domain.sources.dns import resolve_host
from opfor.scenarios.attacksurface.assets.domain.sources.http import (
    fetch_document,
    fetch_url,
    graphql_introspect,
    http_probe,
)
from opfor.scenarios.attacksurface.assets.domain.sources.enumeration import (
    Enumeration,
    certspotter_subdomains,
    otx_subdomains,
    subdomains,
    subdomains_from_otx,
    subdomains_from_vt,
    virustotal_subdomains,
    wayback_paths,
)
from opfor.scenarios.attacksurface.assets.domain.sources.nvd import (
    cves_from_nvd,
    nvd_cves,
)
from opfor.scenarios.attacksurface.assets.domain.sources.osv import (
    cves_from_osv,
    osv_cves,
)
from opfor.scenarios.attacksurface.assets.domain.sources.seeds import (
    hosts_from_file,
    hosts_from_values,
    roots_from_file,
    roots_from_values,
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
    "cves_from_osv",
    "fetch_document",
    "fetch_url",
    "graphql_introspect",
    "hosts_from_file",
    "hosts_from_values",
    "http_probe",
    "info_from_openapi",
    "nvd_cves",
    "operations_from_introspection",
    "osv_cves",
    "otx_subdomains",
    "paths_from_openapi",
    "paths_in_javascript",
    "resolve_host",
    "robots_entries",
    "roots_from_file",
    "roots_from_values",
    "same_host_path",
    "script_sources",
    "sitemap_paths",
    "split_operation",
    "subdomains",
    "subdomains_from_otx",
    "subdomains_from_vt",
    "urls_in_javascript",
    "virustotal_subdomains",
    "wayback_paths",
]

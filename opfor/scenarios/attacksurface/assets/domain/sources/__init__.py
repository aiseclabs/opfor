"""Domain-class sources facade, re-exporting the dns, http, tls, ports, passive, parsers,
javascript, and storage modules.

Resolution, the shared network constants, and address filtering live in `dns`, HTTP transport
in `http`, the TLS posture in `tls`, the port scan in `ports`, passive OSINT source clients in
`passive`, body and document parsers in `parsers`, JavaScript extraction in `javascript`, and
cloud object-storage URL parsing in `storage`. This module gathers the public names in one
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
from opfor.scenarios.attacksurface.assets.domain.sources.ports import port_scan
from opfor.scenarios.attacksurface.assets.domain.sources.tls import tls_probe
from opfor.scenarios.attacksurface.assets.domain.sources.roots import (
    github_declared_roots,
    npm_org_roots,
    propose_roots,
    pypi_org_roots,
    root_from_redirect,
    roots_from_dmarc,
)
from opfor.scenarios.attacksurface.assets.domain.sources.passive import (
    Enumeration,
    cert_sibling_roots,
    certspotter_subdomains,
    cves_from_nvd,
    dnsdumpster_subdomains,
    hosts_from_file,
    nvd_cves,
    otx_subdomains,
    reverse_whois,
    roots_from_file,
    roots_from_reverse_whois,
    sibling_roots_from_issuances,
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

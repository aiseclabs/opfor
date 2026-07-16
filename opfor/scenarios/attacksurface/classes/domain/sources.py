"""Domain-class sources facade, re-exporting http, passive, parsers, javascript, storage.

Transport lives in `http`, passive OSINT source clients in `passive`, body and document
parsers in `parsers`, JavaScript extraction in `javascript`, and cloud object-storage URL
parsing in `storage`. This module gathers the public names in one place so a caller keeps a
single import.
"""

from __future__ import annotations

from opfor.scenarios.attacksurface.classes.domain.http import (
    _TIMEOUT,
    _UA,
    _signal_headers,
    dns_email_posture,
    fetch_document,
    fetch_public_url,
    fetch_readonly,
    fetch_url,
    graphql_introspect,
    http_probe,
    public_addresses,
    resolve_host,
)
from opfor.scenarios.attacksurface.classes.domain.passive import (
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
from opfor.scenarios.attacksurface.classes.domain.parsers import (
    backup_candidates,
    info_from_openapi,
    operations_from_introspection,
    paths_from_openapi,
    robots_entries,
    same_host_path,
    sitemap_paths,
    split_operation,
)
from opfor.scenarios.attacksurface.classes.domain.javascript import (
    _JS_PATH,
    _JS_URL,
    paths_in_javascript,
    script_sources,
    secrets_in_text,
    source_map_from_text,
    urls_in_javascript,
)
from opfor.scenarios.attacksurface.classes.domain.storage import (
    bucket_listable,
    cloud_bucket_from_url,
    cloud_refs_in_text,
)

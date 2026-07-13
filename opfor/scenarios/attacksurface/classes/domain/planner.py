"""Domain-class planner rules, the pipeline that discovers and enriches the domain surface.

Discovery grows the root and subdomain set in MAP. Enrichment resolves each name, probes
the resolvable ones, harvests candidate paths, enumerates interfaces once harvesting has
run across all hosts, then expands any exposed API specification or open introspection.
The rules gate on facts rather than task dependencies, so a name that does not resolve is
never probed, and each rule that touches the target carries the host for scope.

This module reads two capability action-config files, the probe path list and the static-
asset lists, so the planner hands them to the endpoint probe rather than the capability
reading a knowledge file. They are the domain class's own data, so they live under its
knowledge tree.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

import yaml

from opfor.core import Task, World, each
from opfor.scenarios.attacksurface.classes import class_enabled

_KNOWLEDGE = Path(__file__).resolve().parent / "knowledge"

_PATHS = yaml.safe_load((_KNOWLEDGE / "paths.yaml").read_text(encoding="utf-8")) or {}
_PROBE_PATHS = [str(p) for p in (_PATHS.get("paths") or [])]

# The endpoint probe reads no knowledge file, so the planner loads the static-asset lists
# here and hands them to it, the same way it hands the probe path list.
_INTERFACES = yaml.safe_load((_KNOWLEDGE / "interfaces.yaml").read_text(encoding="utf-8")) or {}
_STATIC = _INTERFACES.get("static_assets") or {}
_STATIC_SUFFIXES = [str(s) for s in (_STATIC.get("suffixes") or [])]
_STATIC_PREFIXES = [str(p) for p in (_STATIC.get("prefixes") or [])]

# Secret patterns for the script scan, loaded here and handed to the capability, so no
# capability reads a knowledge file.
_SECRETS = yaml.safe_load((_KNOWLEDGE / "secret_patterns.yaml").read_text(encoding="utf-8")) or {}
_SECRET_PATTERNS = [dict(p) for p in (_SECRETS.get("patterns") or [])]

# Backup name templates for the backup scan, loaded here and handed to the capability, so no
# capability reads a knowledge file.
_BACKUPS = yaml.safe_load((_KNOWLEDGE / "backups.yaml").read_text(encoding="utf-8")) or {}
_BACKUP_APPEND = [str(s) for s in (_BACKUPS.get("append") or [])]
_BACKUP_RENAME = [str(s) for s in (_BACKUPS.get("rename") or [])]
_BACKUP_SWAP = [str(s) for s in (_BACKUPS.get("swap") or [])]

# Cloud bucket affixes and provider list endpoints for the bucket scan, loaded here and handed
# to the capability, so no capability reads a knowledge file.
_BUCKETS = yaml.safe_load((_KNOWLEDGE / "buckets.yaml").read_text(encoding="utf-8")) or {}
_BUCKET_AFFIXES = [str(s) for s in (_BUCKETS.get("affixes") or [])]
_BUCKET_PROVIDERS = [dict(p) for p in (_BUCKETS.get("providers") or [])]


def _live_domains(world: World) -> list:
    """Every domain that answered HTTP, the hosts worth probing."""
    live = []
    for node in world.nodes("domain"):
        http = world.latest("http", node.id)
        if http is not None and http.payload.alive:
            live.append(node)
    return live


def _http_rule(world: World) -> list[Task]:
    """Probe every resolvable domain that has no HTTP fact yet.

    This gates HTTP on a resolved result rather than a task dependency, so a name that
    does not resolve is never probed, and the probe carries the domain name for scope,
    since touching the target's server is a scoped act, not a public read.
    """
    tasks: list[Task] = []
    for node in world.nodes("domain"):
        resolved = world.latest("resolved", node.id)
        if resolved is None or not resolved.payload.resolvable:
            continue
        if world.has_fact(node.id, "http"):
            continue
        tasks.append(Task(capability="domain_http", node=node.id, scope_host=node.payload.name))
    return tasks


def _harvest_rule(world: World) -> list[Task]:
    """Harvest candidate paths on every live host that has not been harvested yet.

    Harvesting comes before probing so a path a host's script names on a sibling host is
    recorded against that sibling before its interfaces are enumerated.
    """
    tasks: list[Task] = []
    for node in _live_domains(world):
        if world.has_fact(node.id, "harvested"):
            continue
        tasks.append(Task(capability="domain_harvest", node=node.id, scope_host=node.payload.name))
    return tasks


def _endpoints_rule(world: World) -> list[Task]:
    """Enumerate interfaces on every live domain, once every live host is harvested.

    The barrier holds probing until harvesting is done across all hosts, so a cross-host
    candidate has landed on its target before that target is probed. Each task carries the
    domain name for scope and the knowledge path list for the capability.
    """
    live = _live_domains(world)
    if any(not world.has_fact(node.id, "harvested") for node in live):
        return []
    tasks: list[Task] = []
    for node in live:
        if world.has_fact(node.id, "endpoints"):
            continue
        tasks.append(Task(capability="domain_endpoints", node=node.id,
                          params={"paths": _PROBE_PATHS, "static_suffixes": _STATIC_SUFFIXES,
                                  "static_prefixes": _STATIC_PREFIXES},
                          scope_host=node.payload.name))
    return tasks


def _is_spec_endpoint(endpoint) -> bool:
    """Whether an endpoint looks like a JSON API specification worth parsing."""
    path = endpoint.path.lower()
    return (("openapi" in path or "swagger" in path or "api-docs" in path)
            and "json" in (endpoint.content_type or "").lower())


def _spec_rule(world: World) -> list[Task]:
    """Parse every reachable API specification endpoint that has not been parsed yet."""
    tasks: list[Task] = []
    for node in world.nodes("endpoint"):
        endpoint = node.payload
        if world.has_fact(node.id, "api_spec") or endpoint.auth_required:
            continue
        if not _is_spec_endpoint(endpoint):
            continue
        host = urlparse(endpoint.url).hostname or ""
        tasks.append(Task(capability="endpoint_expand_spec", node=node.id, scope_host=host))
    return tasks


def _graphql_rule(world: World) -> list[Task]:
    """Introspect every reachable GraphQL endpoint that has not been introspected yet."""
    tasks: list[Task] = []
    for node in world.nodes("endpoint"):
        endpoint = node.payload
        if world.has_fact(node.id, "graphql") or endpoint.auth_required:
            continue
        if not endpoint.path.lower().rstrip("/").endswith("/graphql"):
            continue
        host = urlparse(endpoint.url).hostname or ""
        tasks.append(Task(capability="endpoint_graphql", node=node.id, scope_host=host))
    return tasks


def _source_map_rule(world: World) -> list[Task]:
    """Scan every live host for reachable JavaScript source maps, once per host.

    It reads the target's bundles and their maps, a scoped act, so the task carries the host
    for scope. Gated on its own fact so it runs once.
    """
    tasks: list[Task] = []
    for node in _live_domains(world):
        if world.has_fact(node.id, "source_maps"):
            continue
        tasks.append(Task(capability="source_map_scan", node=node.id,
                          scope_host=node.payload.name))
    return tasks


def _secret_scan_rule(world: World) -> list[Task]:
    """Scan every live host's scripts for secret-like strings, once per host, handing the
    capability the patterns. It reads the target's bundles, so the task carries the host."""
    tasks: list[Task] = []
    for node in _live_domains(world):
        if world.has_fact(node.id, "secrets_in_js"):
            continue
        tasks.append(Task(capability="secret_scan", node=node.id,
                          params={"patterns": _SECRET_PATTERNS}, scope_host=node.payload.name))
    return tasks


def _backup_rule(world: World) -> list[Task]:
    """Probe backup twins of a live host's observed files, once per host, after its interfaces
    are enumerated so the observed file set is complete. Hands the capability the name
    templates, so it reads no knowledge file, and carries the host, since it touches the
    target's server."""
    tasks: list[Task] = []
    for node in _live_domains(world):
        if not world.has_fact(node.id, "endpoints"):
            continue
        if world.has_fact(node.id, "backups"):
            continue
        tasks.append(Task(capability="backup_scan", node=node.id,
                          params={"append": _BACKUP_APPEND, "rename": _BACKUP_RENAME,
                                  "swap": _BACKUP_SWAP},
                          scope_host=node.payload.name))
    return tasks


def _bucket_rule(world: World) -> list[Task]:
    """Check cloud buckets derived from the target's identity, once per run on the org node.
    It runs in ENRICH, after MAP has discovered the roots the names derive from. It hands the
    capability the affixes and provider endpoints, so it reads no knowledge file, and it reads
    only public cloud endpoints, so it needs no scope host."""
    tasks: list[Task] = []
    for node in world.nodes("org"):
        if not class_enabled(node.payload, "domain"):
            continue
        if world.has_fact(node.id, "buckets"):
            continue
        tasks.append(Task(capability="bucket_scan", node=node.id,
                          params={"affixes": _BUCKET_AFFIXES, "providers": _BUCKET_PROVIDERS}))
    return tasks


def _cve_rule(world: World) -> list[Task]:
    """Scan every live host for known vulnerabilities once its surface is enumerated.

    Gating on the endpoints fact holds the scan until the version endpoints have been
    probed, so the identification has that evidence to read. The scan runs once per host,
    gated on its own fact, and touches only public sources, so it needs no scope host.
    """
    tasks: list[Task] = []
    for node in _live_domains(world):
        if not world.has_fact(node.id, "endpoints"):
            continue
        if world.has_fact(node.id, "cve_scanned"):
            continue
        tasks.append(Task(capability="cve_scan", node=node.id))
    return tasks


def map_rules(*, with_registrant: bool):
    """The domain MAP rules, discovery and the evidence pivots. The registrant pivot rides
    only when its keyed source is wired, so a keyless run omits it rather than failing."""
    rules = [
        each("org", run="discover_domains", unless_fact="domains_discovered",
             where=lambda p: class_enabled(p, "domain")),
        each("domain", run="domain_pivot", unless_fact="pivoted",
             where=lambda p: p.name == p.root),
        each("domain", run="domain_subdomains", unless_fact="enumerated",
             where=lambda p: p.name == p.root),
    ]
    if with_registrant:
        rules.append(each("org", run="domain_registrant", unless_fact="registrant",
                          where=lambda p: class_enabled(p, "domain")))
    return rules


def enrich_rules(*, with_cve: bool = False):
    """The domain ENRICH pipeline, resolve then probe then harvest then enumerate, and the
    CVE scan last when its seams are wired, once a host's surface is enumerated."""
    rules = [
        each("domain", run="domain_resolve", unless_fact="resolved"),
        _http_rule,
        _harvest_rule,
        _endpoints_rule,
        _spec_rule,
        _graphql_rule,
        _source_map_rule,
        _secret_scan_rule,
        _backup_rule,
        _bucket_rule,
    ]
    if with_cve:
        rules.append(_cve_rule)
    return rules

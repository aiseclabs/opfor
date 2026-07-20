"""Domain-class planner rules, the pipeline that discovers and enriches the domain surface.

Discovery grows the root and subdomain set in MAP. Enrichment resolves each name, probes
the resolvable ones, harvests candidate paths, enumerates interfaces once harvesting has
run across all hosts, then expands any exposed API specification or open introspection.
The rules gate on facts rather than task dependencies, so a name that does not resolve is
never probed, and each rule that touches the target carries the host for scope.

This module reads two capability action-config files, the probe path list and the static-
asset lists, so the planner hands them to the endpoint probe rather than the capability
reading a knowledge file. They are the domain class's own data, so they live under its
knowledge tree. The files are loaded once at assemble time into a `DomainPlanConfig`, not at
import, so the content root stays swappable and importing the module triggers no file IO.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import yaml


def _validate_secret_patterns(patterns) -> None:
    """Compile every secret pattern regex at load, so a malformed one fails the run loudly
    here rather than being silently skipped during a scan and quietly disabling a whole
    secret class, invariant 5."""
    for pattern in patterns:
        regex = str(pattern.get("regex", ""))
        if not regex:
            continue
        try:
            re.compile(regex)
        except re.error as exc:
            raise RuntimeError(
                f"invalid secret pattern regex for {pattern.get('id', '?')!r}: {exc}") from exc

from opfor.core import Task, World, each
from opfor.scenarios.attacksurface.assets import class_enabled


@dataclass(frozen=True, kw_only=True)
class DomainPlanConfig:
    """The domain class's capability action-config, the paths to probe, the static-asset
    templates, and the secret and backup name templates the planner hands each capability so
    the capability reads no knowledge file, invariant 1. This is action config, not triage
    knowledge. Loaded once at assemble time by `load_plan_config`, so import triggers no IO."""

    probe_paths: tuple[str, ...] = ()
    static_suffixes: tuple[str, ...] = ()
    static_prefixes: tuple[str, ...] = ()
    secret_patterns: tuple[dict, ...] = ()
    backup_append: tuple[str, ...] = ()
    backup_rename: tuple[str, ...] = ()
    backup_swap: tuple[str, ...] = ()


def load_plan_config(knowledge: Path) -> DomainPlanConfig:
    """Load the domain plan config from the class's knowledge tree, once, at build time. So
    the file IO the planner needs happens when a scenario is assembled, never at import."""
    def load(name: str) -> dict:
        path = knowledge / name
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {} if path.exists() else {}

    paths = load("paths.yaml")
    static = load("interfaces.yaml").get("static_assets") or {}
    secrets = load("secret_patterns.yaml")
    backups = load("backups.yaml")
    secret_patterns = tuple(dict(p) for p in (secrets.get("patterns") or []))
    _validate_secret_patterns(secret_patterns)
    return DomainPlanConfig(
        probe_paths=tuple(str(p) for p in (paths.get("paths") or [])),
        static_suffixes=tuple(str(s) for s in (static.get("suffixes") or [])),
        static_prefixes=tuple(str(p) for p in (static.get("prefixes") or [])),
        secret_patterns=secret_patterns,
        backup_append=tuple(str(s) for s in (backups.get("append") or [])),
        backup_rename=tuple(str(s) for s in (backups.get("rename") or [])),
        backup_swap=tuple(str(s) for s in (backups.get("swap") or [])),
    )


def _live_domains(world: World) -> list:
    """Every domain that answered HTTP, the hosts worth probing."""
    live = []
    for node in world.nodes("domain"):
        http = world.latest("http", node.id)
        if http is not None and http.payload.alive:
            live.append(node)
    return live


def _port_rule(world: World) -> list[Task]:
    """Scan each resolvable host's sensitive service ports once. It runs on hosts that resolved
    to an address, since a backend service host need not answer HTTP, and touching the target's
    ports is a probe-tier scoped act, so the task carries the host for scope. Scope retires it
    unauthorized until the operator raises the tier to probe, so a default recon run does not
    port-scan, it only notes that it was skipped."""
    tasks: list[Task] = []
    for node in world.nodes("domain"):
        resolved = world.latest("resolved", node.id)
        if resolved is None or not resolved.payload.resolvable:
            continue
        if world.has_fact(node.id, "ports"):
            continue
        tasks.append(Task(capability="port_scan", node=node.id, scope_target=node.payload.name))
    return tasks


def _tls_rule(world: World) -> list[Task]:
    """Read the TLS posture of every live host once. It runs on hosts that answered HTTP, so a
    name that serves nothing is not probed, and touching the target's port is a scoped act, so
    the task carries the host for scope."""
    tasks: list[Task] = []
    for node in _live_domains(world):
        if world.has_fact(node.id, "tls"):
            continue
        tasks.append(Task(capability="tls", node=node.id, scope_target=node.payload.name))
    return tasks


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
        tasks.append(Task(capability="domain_http", node=node.id, scope_target=node.payload.name))
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
        tasks.append(Task(capability="domain_harvest", node=node.id, scope_target=node.payload.name))
    return tasks


def _permute_paths_rule(world: World) -> list[Task]:
    """Derive principled path candidates on every live host once it is harvested, before the
    interface probe runs, so the probe confirms them against the host's catch-all baseline.
    Gated on the host's harvested fact so it permutes observed paths, and on its own fact so it
    runs once. It reads only gathered paths and makes no request, so it needs no scope host."""
    tasks: list[Task] = []
    for node in _live_domains(world):
        if not world.has_fact(node.id, "harvested"):
            continue
        if world.has_fact(node.id, "path_permuted"):
            continue
        tasks.append(Task(capability="domain_permute_paths", node=node.id))
    return tasks


def _endpoints_rule(world: World, config: DomainPlanConfig) -> list[Task]:
    """Enumerate interfaces on every live domain, once every live host is harvested and its
    observed paths permuted.

    The barrier holds probing until harvesting and permutation are done across all hosts, so a
    cross-host candidate and a derived path have both landed on their target before it is
    probed. Each task carries the domain name for scope and the knowledge path list.
    """
    live = _live_domains(world)
    if any(not world.has_fact(node.id, "harvested") for node in live):
        return []
    if any(not world.has_fact(node.id, "path_permuted") for node in live):
        return []
    tasks: list[Task] = []
    for node in live:
        if world.has_fact(node.id, "endpoints"):
            continue
        tasks.append(Task(capability="domain_endpoints", node=node.id,
                          params={"paths": list(config.probe_paths),
                                  "static_suffixes": list(config.static_suffixes),
                                  "static_prefixes": list(config.static_prefixes)},
                          scope_target=node.payload.name))
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
        tasks.append(Task(capability="endpoint_expand_spec", node=node.id, scope_target=host))
    return tasks


def _spec_probe_rule(world: World) -> list[Task]:
    """Verify the operations each exposed specification declares, once per spec.

    Gated on the api_spec fact so it runs after the spec is parsed, and on its own
    spec_audit fact so it runs once. It probes the target's declared GET operations, a
    scoped recon act, so it carries the host for scope.
    """
    tasks: list[Task] = []
    for node in world.nodes("endpoint"):
        if not world.has_fact(node.id, "api_spec"):
            continue
        if world.has_fact(node.id, "spec_audit"):
            continue
        host = urlparse(node.payload.url).hostname or ""
        tasks.append(Task(capability="endpoint_probe_spec", node=node.id, scope_target=host))
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
        tasks.append(Task(capability="endpoint_graphql", node=node.id, scope_target=host))
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
                          scope_target=node.payload.name))
    return tasks


def _secret_scan_rule(world: World, config: DomainPlanConfig) -> list[Task]:
    """Scan every live host's scripts for secret-like strings, once per host, handing the
    capability the patterns. It reads the target's bundles, so the task carries the host."""
    tasks: list[Task] = []
    for node in _live_domains(world):
        if world.has_fact(node.id, "secrets_in_js"):
            continue
        tasks.append(Task(capability="secret_scan", node=node.id,
                          params={"patterns": list(config.secret_patterns)},
                          scope_target=node.payload.name))
    return tasks


def _backup_rule(world: World, config: DomainPlanConfig) -> list[Task]:
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
                          params={"append": list(config.backup_append),
                                  "rename": list(config.backup_rename),
                                  "swap": list(config.backup_swap)},
                          scope_target=node.payload.name))
    return tasks


def _bucket_rule(world: World) -> list[Task]:
    """Check the cloud buckets the target reveals, once per run on the org node.

    It waits until every domain is resolved and every live host is harvested, so the CNAME and
    referenced-url evidence the scan reads is complete before it fires, not empty because it
    ran before any host was probed. It reads only public cloud endpoints, so it needs no scope
    host."""
    domains = world.nodes("domain")
    if not domains or any(not world.has_fact(node.id, "resolved") for node in domains):
        return []
    if any(not world.has_fact(node.id, "harvested") for node in _live_domains(world)):
        return []
    tasks: list[Task] = []
    for node in world.nodes("org"):
        if not class_enabled(node.payload, "domain"):
            continue
        if world.has_fact(node.id, "buckets"):
            continue
        tasks.append(Task(capability="bucket_scan", node=node.id))
    return tasks


def _profile_rule(world: World) -> list[Task]:
    """Profile every live host once its surface is enumerated, deriving its product, front-end
    frameworks, and fronting into one host_profile fact.

    Gating on the endpoints fact holds it until the version endpoints have been probed, so the
    identification has that evidence to read. It runs once per host, gated on its own fact, and
    reads facts and public sources, never the target, so it needs no scope host.
    """
    tasks: list[Task] = []
    for node in _live_domains(world):
        if not world.has_fact(node.id, "endpoints"):
            continue
        if world.has_fact(node.id, "host_profile"):
            continue
        tasks.append(Task(capability="domain_profile", node=node.id))
    return tasks


def _cve_rule(world: World) -> list[Task]:
    """Look up known vulnerabilities for every live host once it has been profiled.

    Gating on the host_profile fact holds the lookup until the product and version have been
    identified, so it reads that identity rather than deriving its own. It runs once per host,
    gated on its own fact, and touches only public sources, so it needs no scope host.
    """
    tasks: list[Task] = []
    for node in _live_domains(world):
        if not world.has_fact(node.id, "host_profile"):
            continue
        if world.has_fact(node.id, "cve_scanned"):
            continue
        tasks.append(Task(capability="cve_scan", node=node.id))
    return tasks


def _permute_rule(world: World) -> list[Task]:
    """Permute observed labels into candidate subdomains, once per root, after passive
    enumeration has run so the observed set is populated. Gating on the root's `enumerated`
    fact holds the permutation until passive discovery named the labels it permutes, so it
    extends observed evidence rather than firing on an empty set."""
    tasks: list[Task] = []
    for node in world.nodes("domain"):
        payload = node.payload
        if payload.name != payload.root:
            continue
        if not world.has_fact(node.id, "enumerated"):
            continue
        if world.has_fact(node.id, "permuted"):
            continue
        tasks.append(Task(capability="domain_permute", node=node.id))
    return tasks


def map_rules(*, with_registrant: bool):
    """The domain MAP rules, discovery and the evidence pivots. The registrant pivot rides
    only when its keyed source is wired, so a keyless run omits it rather than failing."""
    rules = [
        each("org", run="discover_domains", unless_fact="domains_discovered",
             where=lambda p: class_enabled(p, "domain")),
        each("domain", run="domain_pivot", unless_fact="pivoted",
             where=lambda p: p.name == p.root),
        each("domain", run="declared_roots", unless_fact="declared",
             where=lambda p: p.name == p.root),
        # The redirect declaration is an active HTTP probe, so it carries the root as its scope
        # target and is denied on a discovered out-of-scope sibling root, unlike the passive DMARC
        # declaration above.
        each("domain", run="redirect_roots", unless_fact="redirect_declared",
             where=lambda p: p.name == p.root, scope_target=lambda p: p.name),
        each("domain", run="domain_subdomains", unless_fact="enumerated",
             where=lambda p: p.name == p.root),
        _permute_rule,
    ]
    if with_registrant:
        rules.append(each("org", run="domain_registrant", unless_fact="registrant",
                          where=lambda p: class_enabled(p, "domain")))
    return rules


def enrich_rules(config: DomainPlanConfig, *, with_profile: bool = False, with_cve: bool = False):
    """The domain ENRICH pipeline, resolve then probe then harvest then enumerate, then the host
    profile, then the CVE lookup that reads it, each when its seams are wired and once a host's
    surface is enumerated. The config is the capability action-config the config-driven rules
    hand their capabilities."""
    rules = [
        each("domain", run="domain_resolve", unless_fact="resolved"),
        # Email authentication is a property of the registrable root, so read the DNS posture
        # on roots only. It reads public DNS, so `each` mints it with no scope host and scope
        # waves it through as osint.
        each("domain", run="dns_email", unless_fact="dns_email",
             where=lambda p: p.name == p.root),
        _http_rule,
        _tls_rule,
        _port_rule,
        _harvest_rule,
        _permute_paths_rule,
        lambda world: _endpoints_rule(world, config),
        _spec_rule,
        _spec_probe_rule,
        _graphql_rule,
        _source_map_rule,
        lambda world: _secret_scan_rule(world, config),
        lambda world: _backup_rule(world, config),
        _bucket_rule,
    ]
    if with_profile:
        rules.append(_profile_rule)
    if with_cve:
        rules.append(_cve_rule)
    return rules

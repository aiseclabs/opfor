"""The subdomain-centric report view, the run's world rendered as one record per host.

The findings list answers what is wrong. This answers the run's own shape, the pipeline the scenario
serves: which subdomains were found, what each one is, and the state of the service it runs, the
interfaces reached, the product and version identified, and the CVEs the lookup tied to it. It reads
only the world the engine mutated, no model, so it is a faithful record of what the run observed, and
it folds each finding onto the host it sits on. The generic report in the CLI merges this in, so the
CLI holds no scenario specifics, the same seam the run adapter uses.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from opfor.core import World

# Rank a host's CVEs by score and show the highest, so a long lookup does not bloat the record. The
# total rides alongside, so a slice never reads as the whole set.
_MAX_CVES = 20


def _host_of(where: str) -> str:
    """The hostname a finding's locator points at, so a finding folds onto its subdomain. A locator
    is usually a url, but a bare host is accepted too."""
    parsed = urlsplit(where if "//" in where else f"//{where}")
    return parsed.hostname or where


def _interfaces(world: World, host: str) -> list[dict]:
    """The interfaces reached on `host`, one record per probed endpoint, so the service surface is
    visible even where no finding was minted."""
    out: list[dict] = []
    for node in world.nodes("endpoint"):
        endpoint = node.payload
        if urlsplit(endpoint.url).hostname != host:
            continue
        record: dict[str, Any] = {"path": endpoint.path, "status": endpoint.status,
                                  "auth_required": endpoint.auth_required}
        if endpoint.content_type:
            record["content_type"] = endpoint.content_type
        out.append(record)
    return sorted(out, key=lambda record: record["path"])


def host_records(world: World, findings) -> list[dict]:
    """One record per discovered subdomain that reached a state worth reporting, carrying what the
    host is and the state of its service, with its findings folded in by id."""
    findings_by_host: dict[str, list[str]] = {}
    for finding in findings:
        findings_by_host.setdefault(_host_of(finding.where), []).append(finding.id)

    records: list[dict] = []
    for node in world.nodes("domain"):
        name = node.payload.name
        resolved = world.latest("resolved", node.id)
        http = world.latest("http", node.id)
        profile = world.latest("host_profile", node.id)
        scan = world.latest("cve_scan", node.id)
        resolvable = resolved.payload.resolvable if resolved is not None else None
        live = bool(http is not None and http.payload.alive)
        finding_ids = findings_by_host.get(name, [])
        interfaces = _interfaces(world, name)
        # A subdomain earns a record when it resolved, answered, carries a finding, or exposed an
        # interface, so the report lists the surface that matters, not every passive-only name.
        if not (live or resolvable or finding_ids or interfaces):
            continue
        record: dict[str, Any] = {"subdomain": name, "source": node.payload.source,
                                  "resolvable": resolvable, "live": live}
        if profile is not None:
            identity: dict[str, Any] = {}
            if profile.payload.product:
                identity["product"] = profile.payload.product
            if profile.payload.version:
                identity["version"] = profile.payload.version
            if profile.payload.cpe:
                identity["cpe"] = profile.payload.cpe
            if profile.payload.frameworks:
                identity["frameworks"] = list(profile.payload.frameworks)
            if identity:
                record["identity"] = identity
        if scan is not None and scan.payload.cves:
            ranked = sorted(scan.payload.cves,
                            key=lambda cve: cve.cvss if cve.cvss is not None else -1.0, reverse=True)
            # The match kind, the full total, and the ranked slice ride together under one `cves`
            # object, so the three read as one fact and a slice never reads as the whole set.
            record["cves"] = {
                "match": scan.payload.match,
                "total": len(ranked),
                "items": [{"id": cve.id, "cvss": cve.cvss, "severity": cve.severity}
                          for cve in ranked[:_MAX_CVES]],
            }
        elif scan is None and profile is not None:
            # The host was identified but its CVE lookup never completed, so mark the status
            # unobtained rather than omit it, since an absent `cves` key otherwise reads as a clean
            # no-known-vulnerabilities negative, invariant 5.
            record["cves"] = {"checked": False}
        if interfaces:
            record["interfaces"] = interfaces
        if finding_ids:
            record["findings"] = finding_ids
        records.append(record)
    # The hosts that carry a finding come first, then the merely live, then the rest, each by name,
    # so a reader meets the surface that matters before the quiet inventory.
    return sorted(records, key=lambda record: (not record.get("findings"), not record["live"],
                                               record["subdomain"]))


def report_view(world: World, findings) -> dict:
    """The scenario's structured report contribution, the `hosts` section the CLI merges into the
    run's findings.json. Keyed so a reader, or a later scenario, adds sections without collision."""
    return {"hosts": host_records(world, findings)}

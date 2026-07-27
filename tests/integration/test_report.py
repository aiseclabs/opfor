"""The subdomain-centric report view, built from the world and merged into the run's findings.json.

These lock the scenario report adapter: a host record carries what the host is and its service
state, a dead passive-only name is not listed, a finding folds onto its host, and the generic CLI
report merges the section without knowing what it means.
"""

from __future__ import annotations

import json

from opfor.core import Fact, Node, World
from opfor.core.phase import Phase
from opfor.core.result import CLOSED, Finding, Report
from opfor.scenarios.attacksurface.assets.domain.types import (
    CVE,
    CVEScan,
    DomainData,
    Endpoint,
    HostProfile,
    HTTPProbe,
    Resolved,
)
from opfor.scenarios.attacksurface.report import host_records, report_view


def _world() -> World:
    world = World()
    world.add(Node(id="domain:api.example.com", type="domain",
                   payload=DomainData(name="api.example.com", root="example.com", source="passive")))
    world.absorb([Fact(kind="resolved", about="domain:api.example.com",
                       payload=Resolved(resolvable=True, addresses=("93.184.216.34",)))])
    world.absorb([Fact(kind="http", about="domain:api.example.com",
                       payload=HTTPProbe(alive=True, status=200, url="https://api.example.com/"))])
    world.absorb([Fact(kind="host_profile", about="domain:api.example.com",
                       payload=HostProfile(product="Grafana", version="8.3.0", frameworks=("angular",)))])
    world.absorb([Fact(kind="cve_scan", about="domain:api.example.com",
                       payload=CVEScan(product="Grafana", version="8.3.0", match="version",
                                       cves=(CVE(id="CVE-2021-43798", cvss=7.5, severity="HIGH"),)))])
    world.add(Node(id="endpoint:api/openapi.json", type="endpoint",
                   payload=Endpoint(url="https://api.example.com/openapi.json", path="/openapi.json",
                                    status=200, auth_required=False, content_type="application/json")))
    # a passive-only name that does not resolve, has no service to analyze
    world.add(Node(id="domain:dead.example.com", type="domain",
                   payload=DomainData(name="dead.example.com", root="example.com", source="passive")))
    world.absorb([Fact(kind="resolved", about="domain:dead.example.com",
                       payload=Resolved(resolvable=False))])
    return world


def test_a_host_record_carries_identity_service_state_and_its_findings():
    findings = (Finding(id="finding:kv:api", title="Grafana file read", severity="HIGH",
                        where="https://api.example.com/", data={"kind": "known-vulnerability"}),)
    records = host_records(_world(), findings)
    by_name = {r["subdomain"]: r for r in records}

    api = by_name["api.example.com"]
    assert api["live"] and api["resolvable"]
    assert api["identity"] == {"product": "Grafana", "version": "8.3.0", "frameworks": ["angular"]}
    assert api["cves"]["match"] == "version" and api["cves"]["items"][0]["id"] == "CVE-2021-43798"
    assert api["interfaces"][0]["path"] == "/openapi.json"
    assert api["findings"] == ["finding:kv:api"]  # the finding folded onto its host by url


def test_an_identified_host_with_no_cve_scan_is_marked_unchecked_not_silently_clean():
    # a host identified but whose CVE lookup never completed must not read as no-known-vulns, so
    # the record marks the status unobtained rather than omitting the section, invariant 5
    world = World()
    world.add(Node(id="domain:id.example.com", type="domain",
                   payload=DomainData(name="id.example.com", root="example.com", source="passive")))
    world.absorb([Fact(kind="resolved", about="domain:id.example.com",
                       payload=Resolved(resolvable=True, addresses=("93.184.216.34",)))])
    world.absorb([Fact(kind="http", about="domain:id.example.com",
                       payload=HTTPProbe(alive=True, status=200, url="https://id.example.com/"))])
    world.absorb([Fact(kind="host_profile", about="domain:id.example.com",
                       payload=HostProfile(product="Grafana", version="8.3.0"))])
    # no cve_scan fact: the lookup failed or the run was suspended before it ran
    record = {r["subdomain"]: r for r in host_records(world, ())}["id.example.com"]
    assert record["cves"] == {"checked": False}


def test_a_dead_passive_only_subdomain_is_not_listed():
    # nothing to analyze on a name that does not resolve and answered nothing, so it is not a host
    names = {r["subdomain"] for r in host_records(_world(), ())}
    assert "api.example.com" in names
    assert "dead.example.com" not in names


def test_the_cli_report_merges_the_hosts_section_between_summary_and_findings():
    from opfor.report import _report_json

    report = Report(scenario="attacksurface", status=CLOSED, reached=Phase.CONFIRM,
                    terminal=Phase.CONFIRM,
                    findings=(Finding(id="finding:kv:api", title="t", severity="HIGH",
                                      where="https://api.example.com/"),))
    out = _report_json(report, _world())
    assert list(out).index("hosts") < list(out).index("findings")  # hosts before findings
    assert out["hosts"][0]["subdomain"] == "api.example.com"
    # round-trips as json, the machine-readable contract
    assert json.loads(json.dumps(out))["hosts"][0]["identity"]["product"] == "Grafana"


def test_a_scenario_without_an_adapter_reports_findings_only():
    from opfor.report import _report_json

    report = Report(scenario="mock", status=CLOSED, reached=Phase.TRIAGE, terminal=Phase.TRIAGE)
    out = _report_json(report, _world())
    assert "hosts" not in out  # the generic report adds no section a scenario did not contribute


def test_report_view_is_keyed_so_sections_do_not_collide():
    assert set(report_view(_world(), ())) == {"hosts"}

from __future__ import annotations

from opfor.core import Node, World

from tests.surface_fixtures import _run_capturing


def test_nvd_cves_parses_id_score_severity_and_summary():
    from opfor.scenarios.attacksurface.assets.domain import sources as domains

    reply = {
        "vulnerabilities": [
            {"cve": {
                "id": "CVE-2021-39226",
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
                            "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}]},
                "descriptions": [{"lang": "es", "value": "ignore"}, {"lang": "en", "value": "auth bypass"}],
                "references": [{"url": "https://advisory.example/GHSA-1"},
                               {"url": "https://nvd.example/CVE-2021-39226"}],
            }},
            {"cve": {"id": "", "metrics": {}, "descriptions": []}},
        ]
    }
    cves = domains.cves_from_nvd(reply)
    assert len(cves) == 1
    # the strongest metric wins, v3.1 over v2, the english description is taken, and the
    # advisory links are kept so an exploit poc is anchored to a real source
    assert cves[0] == {
        "id": "CVE-2021-39226", "cvss": 9.8, "severity": "CRITICAL", "summary": "auth bypass",
        "references": ["https://advisory.example/GHSA-1", "https://nvd.example/CVE-2021-39226"]}

def test_nvd_stamps_the_total_match_count_so_a_truncated_page_is_visible():
    from opfor.scenarios.attacksurface.assets.domain.sources import nvd as domains

    # the query matched more than the page held, so each record carries the true total, and a
    # reply that fit in one page carries no misleading total to trip a spurious gap
    stamped = domains._with_total([{"id": "CVE-1"}, {"id": "CVE-2"}], 137)
    assert all(record["available"] == 137 for record in stamped)
    assert "available" not in domains._with_total([{"id": "CVE-1"}], None)[0]


def test_nvd_cves_returns_nothing_for_an_unidentified_product():
    from opfor.scenarios.attacksurface.assets.domain import sources as domains

    # no product means nothing to query, an empty list without a network call
    assert domains.nvd_cves("", "1.0") == []

def test_nvd_keyword_search_uses_the_product_alone_not_the_version(monkeypatch):
    """NVD keyword search matches the description text, where a version rarely appears, so
    the query is the product alone, or a version-bearing product would return nothing."""
    from opfor.scenarios.attacksurface.assets.domain.sources import nvd as domains

    queries = []
    monkeypatch.setattr(domains, "_nvd_fetch", lambda q: queries.append(q) or [])
    domains.nvd_cves("litellm", "1.90.0")
    assert queries == ["keywordSearch=litellm"]

def test_nvd_falls_back_to_a_product_keyword_when_the_cpe_match_is_empty(monkeypatch):
    """A wrong vendor guess or a cve not tagged with the cpe yields an empty cpe match, so
    the query falls back to a product keyword rather than missing a real advisory."""
    from opfor.scenarios.attacksurface.assets.domain.sources import nvd as domains

    queries = []

    def fake_fetch(query):
        queries.append(query)
        if query.startswith("virtualMatchString"):
            return []
        return [{"id": "CVE-2026-40217"}]

    monkeypatch.setattr(domains, "_nvd_fetch", fake_fetch)
    result = domains.nvd_cves("litellm", "1.90.0", cpe="berriai:litellm")
    assert result == [{"id": "CVE-2026-40217", "match": "keyword"}]
    assert len(queries) == 2
    assert queries[0].startswith("virtualMatchString")
    assert queries[1] == "keywordSearch=litellm"

def test_nvd_cpe_match_with_results_does_not_fall_back(monkeypatch):
    from opfor.scenarios.attacksurface.assets.domain.sources import nvd as domains

    queries = []
    monkeypatch.setattr(domains, "_nvd_fetch",
                        lambda q: queries.append(q) or [{"id": "CVE-2020-0001"}])
    result = domains.nvd_cves("grafana", "9.0.0", cpe="grafana:grafana")
    assert result == [{"id": "CVE-2020-0001", "match": "version"}]
    assert len(queries) == 1
    assert queries[0].startswith("virtualMatchString")

def test_nvd_tags_the_match_basis_version_product_or_keyword(monkeypatch):
    """Each record carries how it was matched, so triage weighs a version match apart from a
    product-wide or a bare product-name match."""
    from opfor.scenarios.attacksurface.assets.domain.sources import nvd as domains

    monkeypatch.setattr(domains, "_nvd_fetch", lambda q: [{"id": "CVE-1"}])
    # a cpe match with a version is tied to the affected-version range
    assert domains.nvd_cves("grafana", "9.0.0", cpe="grafana:grafana")[0]["match"] == "version"
    # a cpe match without a version is the product's whole history
    assert domains.nvd_cves("grafana", "", cpe="grafana:grafana")[0]["match"] == "product"
    # no cpe means a keyword text search on the product name
    assert domains.nvd_cves("grafana", "9.0.0")[0]["match"] == "keyword"

def test_nvd_throttle_serializes_calls_to_stay_under_the_rate_limit(monkeypatch):
    from opfor.scenarios.attacksurface.assets.domain.sources import nvd as domains

    clock = {"t": 100.0}
    slept = []
    monkeypatch.setattr(domains.time, "monotonic", lambda: clock["t"])
    monkeypatch.setattr(domains.time, "sleep", lambda s: slept.append(s))
    domains._nvd_next[0] = 0.0

    # the first call does not wait, it only schedules the next slot
    domains._nvd_wait(6.0)
    assert slept == []
    # a second call before the interval has passed blocks until the slot opens
    domains._nvd_wait(6.0)
    assert slept and abs(slept[-1] - 6.0) < 0.01

def test_cve_scan_records_the_identified_product_and_its_cves():
    # the identify seam names the product, the cve seam looks it up, and the scan records
    # both as a raw fact, the agent-driven identification feeding the mechanical lookup
    def identify(evidence):
        assert "host" in evidence
        return {"product": "grafana", "version": "8.0.0", "cpe": "grafana:grafana"}

    def cves(product, version, cpe=""):
        assert (product, version, cpe) == ("grafana", "8.0.0", "grafana:grafana")
        return [{"id": "CVE-2021-39226", "cvss": 9.8, "severity": "CRITICAL", "summary": "auth bypass"}]

    report, _scenario, world = _run_capturing(identify_fn=identify, cve_fn=cves)
    scans = [f.payload for f in world.facts("cve_scan") if f.payload.product]
    assert scans, "expected a cve_scan fact carrying a product"
    assert scans[0].product == "grafana" and scans[0].version == "8.0.0"
    assert any(c.id == "CVE-2021-39226" and c.severity == "CRITICAL" for c in scans[0].cves)

def test_cve_scan_records_the_match_basis_from_the_lookup():
    # the scan records how the lookup matched its list, once, so triage weighs a name match
    # apart from a version match rather than trusting a bare list
    def identify(evidence):
        return {"product": "grafana", "version": "", "cpe": "grafana:grafana"}

    def cves(product, version, cpe=""):
        return [{"id": "CVE-2021-39226", "match": "product"}]

    _report, _scenario, world = _run_capturing(identify_fn=identify, cve_fn=cves)
    scans = [f.payload for f in world.facts("cve_scan") if f.payload.product]
    assert scans and scans[0].match == "product"

def test_cve_scan_records_a_coverage_gap_when_the_lookup_was_truncated():
    # the database matched more CVEs than the bounded page returned, so the kept list is a slice,
    # not the whole set, and the drop stays loud rather than reading as the complete picture
    from opfor.core import Fact, Node, Task, World
    from opfor.scenarios.attacksurface.assets.domain.capabilities import CVELookup
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData, HostProfile

    world = World()
    world.add(Node(id="domain:h", type="domain", payload=DomainData(name="h", root="h", source="s")))
    world.absorb([Fact(kind="host_profile", about="domain:h",
                       payload=HostProfile(product="acme", version="1.0"))])

    def cves(product, version, cpe=""):
        return [{"id": "CVE-1", "match": "keyword", "available": 42}]

    out = CVELookup(cves).run(Task(capability="cve_scan", node="domain:h"), world)
    kinds = [f.kind for f in out.facts]
    assert "cve_scan" in kinds and "coverage_gap" in kinds
    gap = next(f.payload for f in out.facts if f.kind == "coverage_gap")
    assert gap.scan == "cve_scan" and gap.host == "h" and "42" in gap.reasons[0]


def test_cve_scan_records_no_gap_when_the_page_held_the_whole_set():
    # the database returned every CVE it matched, so there is no drop to record, only the scan
    from opfor.core import Fact, Node, Task, World
    from opfor.scenarios.attacksurface.assets.domain.capabilities import CVELookup
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData, HostProfile

    world = World()
    world.add(Node(id="domain:h", type="domain", payload=DomainData(name="h", root="h", source="s")))
    world.absorb([Fact(kind="host_profile", about="domain:h",
                       payload=HostProfile(product="acme", version="1.0"))])

    def cves(product, version, cpe=""):
        return [{"id": "CVE-1", "match": "version", "available": 1}]

    out = CVELookup(cves).run(Task(capability="cve_scan", node="domain:h"), world)
    assert [f.kind for f in out.facts] == ["cve_scan"]


def test_profile_fails_loud_when_identification_errors():
    # a model error while profiling is a loud Failed, never a silent empty result, invariant 5
    def boom(evidence):
        raise RuntimeError("model down")

    report, _scenario, _world = _run_capturing(identify_fn=boom)
    assert any("domain_profile" in note and "model down" in note for note in report.notes)

def test_profile_evidence_surfaces_the_spec_version_from_the_endpoint_body():
    """Host profiling reads a specification's declared version from the endpoint's own body head,
    before any separate parse runs, so a version-bearing spec is not missed."""
    from opfor.core import Node, Task, World
    from opfor.scenarios.attacksurface.assets.domain.capabilities import ProfileHost
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData, Endpoint

    captured = {}

    def identify(evidence):
        captured["evidence"] = evidence
        return {"product": "", "version": "", "cpe": ""}

    world = World()
    world.add(Node(id="domain:api.example.com", type="domain",
                   payload=DomainData(name="api.example.com", root="example.com", source="crt")))
    ep_id = "endpoint:api.example.com/openapi.json"
    body = '{"openapi":"3.1.0","info":{"title":"litellm api","version":"1.90.0"},"paths":{}}'
    world.add(Node(id=ep_id, type="endpoint",
                   payload=Endpoint(url="https://api.example.com/openapi.json", path="/openapi.json",
                                    status=200, auth_required=False,
                                    content_type="application/json", body=body)))

    out = ProfileHost(identify, lambda http: []).run(
        Task(capability="domain_profile", node="domain:api.example.com"), world)
    assert out.facts
    assert "1.90.0" in captured["evidence"]
    assert "litellm api" in captured["evidence"]

def test_cve_render_ranks_by_cvss_and_notes_truncation():
    from opfor.core import Fact
    from opfor.scenarios.attacksurface.assets.domain.types import CVE, CVEScan, DomainData, HTTP, Resolved
    from opfor.scenarios.attacksurface.render import SurfaceRenderer

    world = World()
    world.add(Node(id="domain:h", type="domain", payload=DomainData(name="h", root="h", source="s")))
    world.absorb([
        Fact(kind="resolved", about="domain:h", payload=Resolved(resolvable=True, addresses=("1.2.3.4",))),
        Fact(kind="http", about="domain:h", payload=HTTP(alive=True, status=200, url="https://h/")),
    ])
    # eleven CVEs, the critical one last in database order so a blind head slice would drop it
    cves = tuple(CVE(id=f"CVE-{i}", cvss=1.0, severity="LOW", summary="low") for i in range(10))
    cves += (CVE(id="CVE-CRIT", cvss=9.8, severity="CRITICAL", summary="rce"),)
    world.absorb([Fact(kind="cve_scan", about="domain:h",
                       payload=CVEScan(product="acme", version="1.0", cves=cves))])
    report = "\n".join(SurfaceRenderer(clues=[], takeover=[]).units(world))
    # the highest-scored CVE reaches the report despite being last in database order
    assert "CVE-CRIT" in report
    # the truncation is stated rather than silent
    assert "more CVE(s) not shown" in report

def test_cve_render_states_a_weak_match_basis_so_the_judge_weighs_it():
    from opfor.core import Fact
    from opfor.scenarios.attacksurface.assets.domain.types import CVE, CVEScan, DomainData, HTTP, Resolved
    from opfor.scenarios.attacksurface.render import SurfaceRenderer

    world = World()
    world.add(Node(id="domain:h", type="domain", payload=DomainData(name="h", root="h", source="s")))
    world.absorb([
        Fact(kind="resolved", about="domain:h", payload=Resolved(resolvable=True, addresses=("1.2.3.4",))),
        Fact(kind="http", about="domain:h", payload=HTTP(alive=True, status=200, url="https://h/")),
    ])
    cves = (CVE(id="CVE-1", cvss=7.0, severity="HIGH", summary="x"),)
    world.absorb([Fact(kind="cve_scan", about="domain:h",
                       payload=CVEScan(product="acme", version="", match="keyword", cves=cves))])
    report = "\n".join(SurfaceRenderer(clues=[], takeover=[]).units(world))
    assert "cve match: matched by product name only" in report

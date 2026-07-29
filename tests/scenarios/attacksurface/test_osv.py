"""The OSV ecosystem CVE source, parsed apart from the network.

These lock the record contract the CVE lookup reads: an id that prefers a CVE alias, a severity
mapped into the engine's vocabulary, a base score computed from the CVSS v3 vector OSV carries but
does not score, and the match basis a versioned or unversioned query is tagged with. No network is
touched, a canned reply drives the parse.
"""

from __future__ import annotations

from opfor.scenarios.attacksurface.assets.domain.sources import osv


# A trimmed OSV reply shaped like the live api.osv.dev query response for the npm `vue` package.
_REPLY = {
    "vulns": [
        {
            "id": "GHSA-5j4c-8p2g-v4jx",
            "aliases": ["CVE-2024-9506"],
            "summary": "ReDoS in vue package",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L"}],
            "database_specific": {"severity": "LOW"},
            "references": [{"url": "https://a"}, {"url": "https://b"}, {"url": "https://c"},
                           {"url": "https://d"}],
        },
        {
            # no CVE alias yet, so the record reads as its own GHSA id, and a scope-changed vector
            # exercises the changed-scope branch of the base-score computation
            "id": "GHSA-xxxx-yyyy-zzzz",
            "aliases": [],
            "summary": "Reflected XSS",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}],
            "database_specific": {"severity": "MODERATE"},
        },
        {
            # a v4-only record carries no v3 vector, so no numeric score is claimed, only the label
            "id": "GHSA-v4on-lyxx-only",
            "aliases": ["CVE-2025-0001"],
            "summary": "",
            "details": "detail text used when there is no summary",
            "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"}],
            "database_specific": {"severity": "HIGH"},
        },
    ]
}


def test_a_cve_alias_is_preferred_over_the_advisory_id():
    records = {r["id"]: r for r in osv.cves_from_osv(_REPLY)}
    assert "CVE-2024-9506" in records  # the alias, not GHSA-5j4c-8p2g-v4jx
    assert "GHSA-xxxx-yyyy-zzzz" in records  # no alias, so the advisory id stands


def test_severity_is_mapped_into_the_engine_vocabulary():
    records = {r["id"]: r for r in osv.cves_from_osv(_REPLY)}
    assert records["CVE-2024-9506"]["severity"] == "LOW"
    assert records["GHSA-xxxx-yyyy-zzzz"]["severity"] == "MEDIUM"  # GHSA MODERATE mapped
    assert records["CVE-2025-0001"]["severity"] == "HIGH"


def test_a_base_score_is_computed_from_the_cvss_v3_vector():
    records = {r["id"]: r for r in osv.cves_from_osv(_REPLY)}
    assert records["CVE-2024-9506"]["cvss"] == 3.7  # the published score for this vector
    assert records["GHSA-xxxx-yyyy-zzzz"]["cvss"] == 6.1  # the canonical reflected-XSS score
    # a v4-only record carries no v3 vector, so no number is invented, matching the NVD source
    assert records["CVE-2025-0001"]["cvss"] is None


def test_the_summary_falls_back_to_details_and_references_are_bounded():
    records = {r["id"]: r for r in osv.cves_from_osv(_REPLY)}
    assert records["CVE-2025-0001"]["summary"] == "detail text used when there is no summary"
    assert len(records["CVE-2024-9506"]["references"]) == osv._OSV_MAX_REFS


def test_a_versioned_query_tags_version_and_an_unversioned_query_tags_product(monkeypatch):
    monkeypatch.setattr(osv, "_osv_fetch", lambda body: osv.cves_from_osv(_REPLY))
    versioned = osv.osv_cves("vue", "2.6.14")
    assert versioned[0]["match"] == "version"
    assert versioned[0]["available"] == len(versioned)
    unversioned = osv.osv_cves("vue")
    assert unversioned[0]["match"] == "product"


def test_an_empty_package_does_no_lookup():
    assert osv.osv_cves("", "1.0.0") == []

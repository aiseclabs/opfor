"""Turning a model reply into typed findings: mapping and severity fallback, location grounding
against the report, confidence coercion, and deduplication. Every test runs offline."""

from __future__ import annotations

import json

from opfor.core import MockProvider
from opfor.scenarios.attacksurface.lifecycle.triage import _finding_from_dict

from tests.scenarios.attacksurface.fixtures import _run_capturing


def test_model_findings_are_mapped_to_typed_findings():
    reply = json.dumps({"findings": [{
        "category": "unauthenticated-interface", "title": "Open admin endpoint", "severity": "HIGH",
        "where": "https://admin.example.com/admin", "evidence": "an admin dashboard answered 200",
        "poc": "curl -s https://admin.example.com/admin", "confidence": 0.9,
    }]})
    report, _, _ = _run_capturing(provider=MockProvider(responses=[reply]))
    found = [f for f in report.findings if f.data.get("kind") == "unauthenticated-interface"]
    assert found and found[0].severity == "HIGH"
    assert found[0].where.endswith("/admin")
    # the poc field is the grounder's, an observed safe read grounds to a generated PoC script
    # labeled unverified, so the mapped finding points at the runnable artifact, not the model's raw
    # request. The grounded request preserves the observed url the model named.
    assert found[0].poc.startswith("UNVERIFIED") and ".py" in found[0].poc
    assert found[0].data["poc_request"]["url"] == "https://admin.example.com/admin"
    assert found[0].data["confidence"] == 0.9


def test_unknown_severity_falls_back_to_class_impact_then_medium():
    ids = frozenset({"known-vulnerability"})
    impacts = {"known-vulnerability": "HIGH"}
    # a known class with a bad severity anchors on the class impact
    f = _finding_from_dict({"where": "u", "category": "Known-Vulnerability", "severity": "WOBBLY"},
                           known_ids=ids, impacts=impacts)
    assert f.severity == "HIGH"
    # an unknown class with a bad severity falls back to MEDIUM
    g = _finding_from_dict({"where": "u", "severity": "WOBBLY"}, known_ids=ids, impacts=impacts)
    assert g.severity == "MEDIUM"


def test_finding_without_a_location_is_dropped():
    assert _finding_from_dict({"severity": "HIGH", "title": "no where"}) is None


def test_a_finding_host_that_is_only_a_substring_of_a_report_host_is_dropped():
    data = {"category": "unauthenticated-interface", "title": "x", "severity": "HIGH",
            "where": "https://example.com/admin"}
    # the report only mentions notexample.com, so example.com must not be accepted as a substring
    assert _finding_from_dict(data, report_text="server notexample.com only") is None
    # the host genuinely present as a whole name is kept
    assert _finding_from_dict(data, report_text="host example.com admin panel") is not None


def test_category_is_normalized_onto_the_known_class_ids():
    ids = frozenset({"known-vulnerability"})
    f = _finding_from_dict({"where": "u", "category": "Known-Vulnerability", "severity": "medium"},
                           known_ids=ids)
    assert f.data["kind"] == "known-vulnerability"
    assert f.id == "finding:known-vulnerability:u"
    # an unrecognized class collapses to other, so the id stays stable for dedup
    other = _finding_from_dict({"where": "u", "category": "made-up-thing"}, known_ids=ids)
    assert other.data["kind"] == "other"
    assert other.id == "finding:other:u"


def test_malformed_findings_are_dropped_loudly_with_a_degraded_marker():
    import json

    from opfor.core import MockProvider
    from opfor.scenarios.attacksurface.lifecycle.triage import SurfaceTriage

    reply = json.dumps({"findings": [
        {"category": "unauthenticated-interface", "title": "ok", "severity": "HIGH",
         "where": "https://h/a"},
        {"category": "x"},          # no location, dropped
        "not-an-object",            # not a dict, dropped
    ]})
    triage = SurfaceTriage([], provider=MockProvider(responses=[reply]), model="m")
    found = triage._judge_chunk("## some host block\nhttps://h/a")
    # the two malformed entries do not vanish silently, a degraded marker says so
    degraded = [f for f in found if f.data.get("kind") == "triage_degraded"]
    assert degraded and degraded[0].data["dropped"] == 2
    assert degraded[0].severity == "INFO"
    # the well-formed finding still comes through
    assert any(f.where == "https://h/a" for f in found)


def test_a_finding_whose_location_is_not_in_the_report_is_dropped():
    import json

    from opfor.core import MockProvider
    from opfor.scenarios.attacksurface.lifecycle.triage import SurfaceTriage

    reply = json.dumps({"findings": [
        {"category": "unauthenticated-interface", "title": "real", "severity": "HIGH",
         "where": "https://h/real"},
        {"category": "unauthenticated-interface", "title": "invented", "severity": "HIGH",
         "where": "https://evil.invented/x"},
    ]})
    triage = SurfaceTriage([], provider=MockProvider(responses=[reply]), model="m")
    found = triage._judge_chunk("## h\nhttps://h/real")
    kept = [f for f in found if f.data.get("kind") != "triage_degraded"]
    # the location the model invented is not in the report, so it is dropped, not minted
    assert [f.where for f in kept] == ["https://h/real"]
    degraded = [f for f in found if f.data.get("kind") == "triage_degraded"]
    assert degraded and degraded[0].data["dropped"] == 1


def test_confidence_is_coerced_to_a_float_or_none():
    from opfor.scenarios.attacksurface.lifecycle.triage import _confidence
    # a string, a null, or an out-of-range value never lands raw in the structured axes
    assert _confidence("high") is None
    assert _confidence(None) is None
    assert _confidence(1.5) == 1.0
    assert _confidence(0.7) == 0.7


def test_dedup_merges_same_class_and_location_taking_max_severity_and_union_evidence():
    from opfor.core.result import Finding
    from opfor.scenarios.attacksurface.lifecycle.triage import SurfaceTriage
    a = Finding(id="finding:known-vulnerability:h", title="known vulns", severity="MEDIUM",
                where="h", evidence="CVE-1 affects the running version")
    b = Finding(id="finding:known-vulnerability:h", title="known vulns", severity="HIGH",
                where="h", evidence="CVE-2 affects the running version")
    out = SurfaceTriage._dedup([a, b])
    # one finding at this class and location, at the higher severity, carrying both evidences
    assert len(out) == 1
    assert out[0].severity == "HIGH"
    assert "CVE-1" in out[0].evidence and "CVE-2" in out[0].evidence


def test_dedup_collapses_title_and_scheme_variance_but_keeps_distinct_paths():
    from opfor.core.result import Finding
    from opfor.scenarios.attacksurface.lifecycle.triage import SurfaceTriage
    # same class + location worded two ways, plus a scheme/slash variant, collapse to one
    v1 = Finding(id="finding:unauthenticated-interface:https://h/a",
                 title="open endpoint", severity="LOW", where="https://h/a")
    v2 = Finding(id="finding:unauthenticated-interface:https://h/a/",
                 title="unauthenticated endpoint", severity="LOW", where="https://h/a/")
    # a genuinely different path stays a separate finding
    other = Finding(id="finding:unauthenticated-interface:https://h/b",
                    title="open endpoint", severity="LOW", where="https://h/b")
    out = SurfaceTriage._dedup([v1, v2, other])
    assert len(out) == 2
    assert {f.where for f in out} == {"https://h/a", "https://h/b"}

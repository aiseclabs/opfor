"""Finding grounding: a finding is marked reproducible only when its safe-read proof names a GET
the surface actually recorded, apart from the triage judgment in test_surface_triage."""

from __future__ import annotations


import json

from opfor.core import MockProvider, Node, World
from tests.scenarios.attacksurface.fixtures import (
    _make,
)


def test_grounding_attaches_a_poc_request_only_for_an_observed_safe_read():
    """Strict grounding: a finding is marked reproducible only when its safe-read proof of
    concept names a GET the surface actually recorded, never a request the model invented."""
    from opfor.core import Fact
    from opfor.scenarios.attacksurface.assets.domain.types import (
        DomainData, Endpoint, SpecAudit, SpecOperation)
    from opfor.core.result import Finding
    from opfor.scenarios.attacksurface.assets.domain.grounding import FindingGrounder

    world = World()
    world.add(Node(id="domain:api.example.com", type="domain",
                   payload=DomainData(name="api.example.com", root="example.com", source="crt")))
    ep_id = "endpoint:api.example.com/config/all"
    world.add(Node(id=ep_id, type="endpoint",
                   payload=Endpoint(url="https://api.example.com/config/all", path="/config/all",
                                    status=200, auth_required=False, content_type="application/json")))
    spec_ep = "endpoint:api.example.com/openapi.json"
    world.add(Node(id=spec_ep, type="endpoint",
                   payload=Endpoint(url="https://api.example.com/openapi.json", path="/openapi.json",
                                    status=200, content_type="application/json")))
    world.absorb([Fact(kind="spec_audit", about=spec_ep, payload=SpecAudit(
        base="https://api.example.com/openapi.json",
        operations=(SpecOperation(path="/tasks/active", methods="GET", verified=True,
                                  status=200, content_type="application/json"),)))])

    grounded = Finding(id="f1", title="open config", severity="HIGH",
                       where="https://api.example.com/config/all",
                       poc="safe read: curl -s https://api.example.com/config/all")
    spec_op = Finding(id="f2", title="open op", severity="MEDIUM",
                      where="https://api.example.com/openapi.json",
                      poc="safe read: curl -s https://api.example.com/tasks/active")
    invented = Finding(id="f3", title="guessed path", severity="HIGH",
                       where="https://api.example.com/openapi.json",
                       poc="safe read: curl -s https://api.example.com/secret/never-probed")
    exploit = Finding(id="f4", title="rce", severity="HIGH",
                      where="https://api.example.com/config/all",
                      poc="requires authorized exploitation: curl https://api.example.com/config/all")

    out = FindingGrounder().run(world, (grounded, spec_op, invented, exploit))
    by_id = {f.id: f for f in out}
    # grounding returns one finding per input finding, minting none and dropping none
    assert len(out) == 4
    # an observed endpoint GET grounds the request, carrying the real receipt and a status matcher
    # so the generated script decides PASS or FAIL rather than leaving the reader to eyeball it
    req = by_id["f1"].data["poc_request"]
    assert req["method"] == "GET" and req["url"] == "https://api.example.com/config/all"
    assert req["urls"] == ["https://api.example.com/config/all"]
    assert req["expect"] == "HTTP 200 application/json" and req["source"] == f"endpoint:{ep_id}"
    assert req["matchers"] == [{"type": "status", "part": "body", "values": ["200"], "condition": "or"}]
    assert req["script"] == "poc/poc-api-example-com.py"
    # the grounder generates a self-contained stdlib script and stores its text, so the run can
    # write one runnable PoC file per grounded finding
    script = by_id["f1"].data["poc_script"]
    assert script.startswith("#!/usr/bin/env python3") and "urllib.request" in script
    compile(script, "<poc>", "exec")
    # a verified specification operation grounds too
    assert by_id["f2"].data["poc_request"]["url"] == "https://api.example.com/tasks/active"
    # a url no capability observed is never marked reproducible
    assert "poc_request" not in by_id["f3"].data
    # an exploit proof of concept is never grounded as a safe read
    assert "poc_request" not in by_id["f4"].data
    # the grounder is the sole authority for the final poc field. A grounded finding points at the
    # generated script labeled unverified, since this run never sends it to the target.
    assert by_id["f1"].poc.startswith("UNVERIFIED")
    assert "poc/poc-api-example-com.py" in by_id["f1"].poc
    # an ungroundable safe read gets an honest message, never a fabricated command or script
    assert "no reproducible" in by_id["f3"].poc.lower() and "poc_script" not in by_id["f3"].data
    # an ungroundable exploit says the demonstration would need authorized exploitation this run
    # does not perform, again with no fabricated command
    assert "authorized exploitation" in by_id["f4"].poc.lower() and "curl" not in by_id["f4"].poc
    # grounding never mutates the input finding in place, it returns a new object, so the
    # original stays clean and Finding.data is effectively immutable
    assert "poc_request" not in grounded.data
    assert by_id["f1"] is not grounded


def test_a_version_matched_cve_keeps_the_model_poc_a_weaker_match_does_not():
    """Tier 2 grounding: a known vulnerability matched on the running version keeps the model's own
    written PoC, labelled unverified and not confirmed against this instance, even when no safe read
    was observed. A CVE matched only on the product name, not the version, does not, since the
    instance is not established as affected, invariant 5."""
    from opfor.core import Fact
    from opfor.core.result import Finding
    from opfor.scenarios.attacksurface.assets.domain.types import CVE, CVEScan, DomainData
    from opfor.scenarios.attacksurface.assets.domain.grounding import FindingGrounder

    world = World()
    world.add(Node(id="domain:vers.example.com", type="domain",
                   payload=DomainData(name="vers.example.com", root="example.com", source="crt")))
    world.add(Node(id="domain:prod.example.com", type="domain",
                   payload=DomainData(name="prod.example.com", root="example.com", source="crt")))
    cve = CVE(id="CVE-2021-43798", cvss=7.5, severity="HIGH", summary="path traversal")
    world.absorb([Fact(kind="cve_scan", about="domain:vers.example.com",
                       payload=CVEScan(product="grafana", version="8.3.0", match="version",
                                       cves=(cve,)))])
    world.absorb([Fact(kind="cve_scan", about="domain:prod.example.com",
                       payload=CVEScan(product="grafana", version="", match="product",
                                       cves=(cve,)))])

    # a version-matched CVE whose safe-read poc names a url the surface never observed
    versioned = Finding(id="v1", title="CVE-2021-43798 in Grafana", severity="HIGH",
                        where="https://vers.example.com/",
                        poc="safe read: curl -s https://vers.example.com/public/plugins/x/../../etc/passwd")
    # the same CVE, but matched only on the product name, not the running version
    unversioned = Finding(id="p1", title="CVE-2021-43798 in Grafana", severity="HIGH",
                          where="https://prod.example.com/",
                          poc="safe read: curl -s https://prod.example.com/public/plugins/x/../../etc/passwd")

    by_id = {f.id: f for f in FindingGrounder().run(world, (versioned, unversioned))}
    # the version match keeps the model's writeup, labelled unverified and unconfirmed, but does not
    # dress it as an opfor-generated script since no observed request grounds it
    assert by_id["v1"].poc.startswith("UNVERIFIED")
    assert "not confirmed against this instance" in by_id["v1"].poc
    assert "curl -s https://vers.example.com/public/plugins" in by_id["v1"].poc
    assert "poc_request" not in by_id["v1"].data and "poc_script" not in by_id["v1"].data
    # a product-only match is not enough to assert a version-specific PoC, so it stays ungrounded
    assert "no reproducible" in by_id["p1"].poc.lower()
    assert "poc_script" not in by_id["p1"].data


def test_triage_judge_mints_findings_and_mutates_no_world_node():
    """Triage judges, and only judges. Neither the judge nor the post-triage grounder adds a
    finding node to the world, keeping world mutation out of triage, invariant 2. The grounder
    only writes the poc field and a poc_request in the finding's data, it materializes nothing,
    and the scenario wires it as the post-triage step."""
    from opfor.core import Fact
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData, Endpoint, Resolved
    from opfor.scenarios.attacksurface.assets.domain.grounding import FindingGrounder
    from opfor.scenarios.attacksurface.assets.domain.triage import SurfaceTriage

    world = World()
    world.add(Node(id="domain:api.example.com", type="domain",
                   payload=DomainData(name="api.example.com", root="example.com", source="crt")))
    # a resolved fact, so the resolution caveat does not suppress model judgment
    world.absorb([Fact(kind="resolved", about="domain:api.example.com",
                       payload=Resolved(resolvable=True, addresses=("1.2.3.4",)))])
    world.add(Node(id="endpoint:api.example.com/.env", type="endpoint",
                   payload=Endpoint(url="https://api.example.com/.env", path="/.env",
                                    status=200, auth_required=False, content_type="text/plain")))
    finder = json.dumps({"findings": [{
        "category": "missing-authentication", "title": "Exposed .env", "severity": "MEDIUM",
        "where": "https://api.example.com/.env", "evidence": "a dotenv path answered 200",
        "poc": "safe read: curl -s https://api.example.com/.env"}]})
    triage = SurfaceTriage([], provider=MockProvider(responses=[finder]), model="m")

    findings = tuple(triage.judge(world))
    # judge mints the finding but adds no finding node, and neither does the grounder
    assert any(f.where == "https://api.example.com/.env" for f in findings)
    assert not world.nodes("finding")
    grounded = FindingGrounder().run(world, findings)
    assert len(grounded) == len(findings)  # one finding per input, none minted, none dropped
    assert not world.nodes("finding")  # the grounder writes the poc field, it materializes nothing
    # the scenario wires the grounder as its post-triage step
    assert isinstance(_make().grounding, FindingGrounder)

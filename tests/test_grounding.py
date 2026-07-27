"""Finding grounding: a finding is marked reproducible only when its safe-read proof names a GET
the surface actually recorded, apart from the triage judgment in test_surface_triage."""

from __future__ import annotations


import json

from opfor.core import MockProvider, Node, World
from tests.surface_fixtures import (
    _make,
)


def test_grounding_attaches_a_poc_request_only_for_an_observed_safe_read():
    """Strict grounding: a finding is marked reproducible only when its safe-read proof of
    concept names a GET the surface actually recorded, never a request the model invented."""
    from opfor.core import Fact
    from opfor.scenarios.attacksurface.assets.domain.types import (
        DomainData, Endpoint, SpecAudit, SpecOperation)
    from opfor.core.result import Finding
    from opfor.scenarios.attacksurface.lifecycle.grounding import FindingGrounder

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


def test_a_versioned_cve_finding_grounds_on_the_recipe_across_every_candidate_path():
    """A known-vulnerability finding whose CVE the lookup tied to the running version grounds on the
    recipe: every candidate path becomes a url, the recipe's headers and matchers ride into the
    request, and the generated script decides PASS or FAIL by the recipe's own fire condition."""
    from opfor.core import Fact
    from opfor.scenarios.attacksurface.assets.domain.types import (
        CVE, CVEScan, DomainData, HTTP)
    from opfor.scenarios.attacksurface.assets.domain.nuclei import Matcher
    from opfor.core.result import Finding
    from opfor.scenarios.attacksurface.lifecycle.grounding import (
        FindingGrounder, ReproductionRecipe)

    world = World()
    world.add(Node(id="domain:g.example.com", type="domain",
                   payload=DomainData(name="g.example.com", root="example.com", source="crt")))
    world.absorb([Fact(kind="http", about="domain:g.example.com",
                       payload=HTTP(alive=True, status=200, url="https://g.example.com/"))])
    world.absorb([Fact(kind="cve_scan", about="domain:g.example.com", payload=CVEScan(
        product="Grafana", version="8.3.0", match="version",
        cves=(CVE(id="CVE-2021-43798"),)))])
    recipe = ReproductionRecipe(
        cve="CVE-2021-43798", method="GET",
        paths=("/public/plugins/alertlist/../../../etc/passwd", "/public/plugins/alertlist/../../../conf/defaults.ini"),
        expect="a file read confirms the traversal",
        matchers=(Matcher(type="regex", part="body", values=("root:.*:0:",), condition="or"),
                  Matcher(type="status", part="body", values=("200",), condition="or")),
        matchers_condition="and")
    finding = Finding(id="v1", title="Grafana CVE-2021-43798 path traversal", severity="HIGH",
                      where="https://g.example.com", data={"kind": "known-vulnerability"})

    out = FindingGrounder(reproductions=(recipe,)).run(world, (finding,))
    req = out[0].data["poc_request"]
    assert req["urls"] == [
        "https://g.example.com/public/plugins/alertlist/../../../etc/passwd",
        "https://g.example.com/public/plugins/alertlist/../../../conf/defaults.ini"]
    assert req["source"] == "reproduction:CVE-2021-43798"
    assert {"type": "status", "part": "body", "values": ["200"], "condition": "or"} in req["matchers"]
    assert req["script"] == "poc/cve-2021-43798-g-example-com.py"
    script = out[0].data["poc_script"]
    assert "root:.*:0:" in script and "defaults.ini" in script
    compile(script, "<poc>", "exec")


def test_triage_judge_mints_findings_and_mutates_no_world_node():
    """Triage judges, and only judges. Neither the judge nor the post-triage grounder adds a
    finding node to the world, keeping world mutation out of triage, invariant 2. The grounder
    only writes the poc field and a poc_request in the finding's data, it materializes nothing,
    and the scenario wires it as the post-triage step."""
    from opfor.core import Fact
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData, Endpoint, Resolved
    from opfor.scenarios.attacksurface.lifecycle.grounding import FindingGrounder
    from opfor.scenarios.attacksurface.lifecycle.triage import SurfaceTriage

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
        "category": "unauthenticated-interface", "title": "Exposed .env", "severity": "MEDIUM",
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

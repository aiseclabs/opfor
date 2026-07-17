from __future__ import annotations

import json

import pytest

from opfor.core import Budget, MockProvider, Node, Phase, Scope, World, run
from opfor.core.result import CLOSED
from opfor.scenarios.attacksurface import build
from opfor.scenarios.attacksurface.lifecycle.triage import TriageError, _finding_from_dict
from opfor.scenarios.attacksurface.types import Org

from tests.surface_fixtures import *


def test_takeover_clue_and_class_are_surfaced():
    _, sc, _ = _run_capturing()
    p = _prompt(sc)
    assert "cdn.example.com" in p
    assert "matched Amazon S3 unclaimed-resource page" in p
    # the takeover knowledge class is selected by the unclaimed-page signal
    assert "Subdomain Takeover" in _knowledge(sc)


def test_dangling_name_is_surfaced():
    _, sc, _ = _run_capturing()
    p = _prompt(sc)
    assert "old.example.com" in p
    assert "does not resolve, seen only passively" in p


def test_takeover_catalogue_is_expanded_and_a_new_signature_raises_its_clue():
    from opfor.core import Fact
    from opfor.scenarios.attacksurface.assets.domain import KNOWLEDGE
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData, HTTP as HTTPData
    from opfor.scenarios.attacksurface.render import SurfaceRenderer
    from opfor.scenarios.attacksurface.lifecycle.triage import _load_takeover

    takeover = _load_takeover(KNOWLEDGE / "takeover.yaml")
    services = {service for service, _ in takeover}
    assert {"Zendesk", "Kinsta", "UserVoice"} <= services
    # every signature is non-empty and lowercased, so the lowercased-body match is reliable
    for service, signature in takeover:
        assert signature and signature == signature.lower()

    # a body carrying a newly added unclaimed-page signature raises its clue for the judge
    world = World()
    world.add(Node(id="domain:h.example.com", type="domain",
                   payload=DomainData(name="h.example.com", root="example.com", source="hint")))
    world.absorb((Fact(kind="http", about="domain:h.example.com",
                       payload=HTTPData(alive=True, status=404, url="https://h.example.com/",
                                        body="<html>help center closed</html>")),))
    text = "\n".join(SurfaceRenderer([], takeover).units(world))
    assert "matched Zendesk unclaimed-resource page" in text


def test_dangling_cname_target_is_surfaced_for_takeover_judgment():
    # the CNAME target is the most direct takeover evidence, a dangling name pointing at an
    # unclaimed service, so it must reach the model rather than being reduced to a bool
    _, sc, _ = _run_capturing()
    p = _prompt(sc)
    assert "CNAME to old-app.herokuapp.com" in p


def test_interesting_surface_class_is_always_present_with_the_admin_host():
    _, sc, _ = _run_capturing()
    assert "https://admin.example.com/admin" in _prompt(sc)
    assert "Interesting Non-Production" in _knowledge(sc)


def test_exposed_git_clue_and_class_are_surfaced():
    _, sc, _ = _run_capturing()
    assert "matched exposed-git" in _prompt(sc)
    assert "Sensitive File Exposure" in _knowledge(sc)


def test_exposed_env_clue_is_surfaced():
    _, sc, _ = _run_capturing()
    assert "matched exposed-env" in _prompt(sc)


def test_authenticated_endpoint_is_excluded_from_the_surface():
    # /metrics answered 401, so the capability marks it auth_required and triage keeps it
    # out of the surface the model judges, it is already protected
    _, sc, world = _run_capturing()
    eps = {n.id: n.payload for n in world.nodes("endpoint")}
    assert eps["endpoint:admin.example.com/metrics"].auth_required is True
    assert "https://admin.example.com/metrics" not in _prompt(sc)


def test_reachable_interface_is_surfaced_for_the_model_to_judge():
    _, sc, _ = _run_capturing()
    assert "https://admin.example.com/admin" in _prompt(sc)


def test_public_by_design_paths_are_explained_to_the_model():
    # robots.txt is reachable, so it is surfaced, and the knowledge tells the model it is
    # public by design, the judgment is the model's, not a suppression in code
    _, sc, _ = _run_capturing()
    assert "https://example.com/robots.txt" in _prompt(sc)
    assert "public by design" in _knowledge(sc)


def test_login_redirect_location_is_surfaced_for_judgment():
    # /portal 302s to a login flow, so the redirect target is surfaced for the model to
    # judge it protected, rather than a keyword rule deciding in code
    _, sc, world = _run_capturing()
    assert world.node("endpoint:admin.example.com/portal") is not None
    assert "redirect to https://admin.example.com/login" in _prompt(sc)


def test_refusal_body_is_surfaced_for_judgment():
    _, sc, _ = _run_capturing()
    p = _prompt(sc)
    assert "https://admin.example.com/private" in p
    assert "unauthorized" in p


def test_declared_api_surface_is_surfaced():
    _, sc, world = _run_capturing()
    specs = [f.payload for f in world.facts("api_spec")]
    assert any(s.count == 2 and "GET /users" in s.paths for s in specs)
    assert "2 operations" in _prompt(sc)


def test_graphql_introspection_is_surfaced():
    _, sc, world = _run_capturing()
    schemas = [f.payload for f in world.facts("graphql")]
    assert any(s.enabled and s.count == 3 and "query:me" in s.operations for s in schemas)
    assert "graphql introspection https://admin.example.com/graphql" in _prompt(sc)


def test_graphql_without_operations_is_not_surfaced():
    # an endpoint can answer the POST yet name no operation, which is not usable
    # introspection, so it must not reach the model as a declared surface
    def empty(name, path="/graphql"):
        return {"__schema": {"queryType": {"fields": []}}}

    _, sc, _ = _run_capturing(introspect_fn=empty)
    assert "graphql introspection" not in _prompt(sc)


def test_empty_env_body_yields_no_exposure_clue():
    # a host that serves an empty 200 for /.env has no KEY=value body, so the deterministic
    # clue must not fire, the clue asserts on content, not the path
    from opfor.scenarios.attacksurface.assets.domain.types import Endpoint

    sc = _make()
    empty = Endpoint(url="https://cf.example.com/.env", path="/.env", status=200, body="")
    real = Endpoint(url="https://x/.env", path="/.env", status=200, body="db_password=secret\napi_key=abc")
    assert sc.triage._renderer._exposure_clues(empty) == []
    assert any("exposed-env" in c for c in sc.triage._renderer._exposure_clues(real))


def test_resolution_failure_suppresses_the_model_call():
    # with the resolver down triage does not ask the model to judge an unreachable surface
    def none_resolve(name):
        return {"resolvable": False, "addresses": ()}

    _, sc, _ = _run_capturing(_seed(classes=("domain",)), resolve_fn=none_resolve)
    assert sc.triage._provider.calls == []


def test_model_findings_are_mapped_to_typed_findings():
    reply = json.dumps({"findings": [{
        "category": "sensitive-file-exposure", "title": "Exposed .git config", "severity": "HIGH",
        "where": "https://admin.example.com/.git/config", "evidence": "a git config section is present",
        "poc": "curl -s https://admin.example.com/.git/config", "confidence": 0.9,
    }]})
    report, _, _ = _run_capturing(provider=MockProvider(responses=[reply]))
    git = [f for f in report.findings if f.data.get("kind") == "sensitive-file-exposure"]
    assert git and git[0].severity == "HIGH"
    assert git[0].where.endswith("/.git/config")
    assert git[0].poc.startswith("curl")
    assert git[0].data["confidence"] == 0.9


def test_grounding_attaches_a_poc_request_only_for_an_observed_safe_read():
    """Strict grounding: a finding is marked reproducible only when its safe-read proof of
    concept names a GET the surface actually recorded, never a request the model invented."""
    from opfor.core import Fact, Node
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
    # an observed endpoint GET grounds the request, carrying the real receipt
    assert by_id["f1"].data["poc_request"] == {
        "method": "GET", "url": "https://api.example.com/config/all",
        "expect": "HTTP 200 application/json", "source": f"endpoint:{ep_id}"}
    # a verified specification operation grounds too
    assert by_id["f2"].data["poc_request"]["url"] == "https://api.example.com/tasks/active"
    # a url no capability observed is never marked reproducible
    assert "poc_request" not in by_id["f3"].data
    # an exploit proof of concept is never grounded as a safe read
    assert "poc_request" not in by_id["f4"].data
    # grounding never mutates the input finding in place, it returns a new object, so the
    # original stays clean and Finding.data is effectively immutable
    assert "poc_request" not in grounded.data
    assert by_id["f1"] is not grounded


def test_triage_judge_mints_findings_and_mutates_no_world_node():
    """Triage judges, and only judges. Materializing a finding as a world node is the
    post-triage grounder's job now, so judge adds no node, keeping world mutation out of
    triage, invariant 2. The grounder materializes it, and the scenario wires it as the
    post-triage step."""
    from opfor.core import Fact, MockProvider, Node
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
        "category": "sensitive-file-exposure", "title": "Exposed .env", "severity": "MEDIUM",
        "where": "https://api.example.com/.env", "evidence": "a dotenv path answered 200",
        "poc": "safe read: curl -s https://api.example.com/.env"}]})
    triage = SurfaceTriage([], provider=MockProvider(responses=[finder]), model="m")

    findings = tuple(triage.judge(world))
    # judge mints the finding but adds no finding node, world mutation is the grounder's job
    assert any(f.where == "https://api.example.com/.env" for f in findings)
    assert not world.nodes("finding")
    grounded = FindingGrounder().run(world, findings)
    assert len(grounded) == len(findings)  # one finding per input, none minted, none dropped
    assert world.nodes("finding")  # the grounded finding is now materialized for reproduce
    # the scenario wires the grounder as its post-triage step
    assert isinstance(_make().post_triage, FindingGrounder)


def test_importing_the_scenario_builds_nothing_until_requested():
    """The eager module-level build is gone, so importing the package or the registry
    constructs no provider and reads no knowledge tree. A scenario is built on first use,
    keeping import cheap and side-effect free."""
    import opfor.scenarios.attacksurface as pkg
    from opfor.scenarios import registry

    # the eager ATTACKSURFACE singleton no longer exists, building is on demand
    assert not hasattr(pkg, "ATTACKSURFACE")
    scenario = registry.get_scenario("attacksurface")
    assert scenario.name == pkg.NAME


def test_get_scenario_rebuilds_so_a_changed_environment_is_not_frozen(monkeypatch):
    """The registry does not memoize the built scenario. The attack-surface build reads the
    model from the environment, so a second call after the environment changes must see the
    new value rather than a frozen first build. This is the regression guard for the cache
    that used to freeze the provider, model, and triage mode on first use."""
    from opfor.scenarios import registry

    monkeypatch.setenv("OPFOR_MODEL", "model-first")
    first = registry.get_scenario("attacksurface")
    assert first.triage._model == "model-first"

    monkeypatch.setenv("OPFOR_MODEL", "model-second")
    second = registry.get_scenario("attacksurface")
    assert second.triage._model == "model-second"
    assert first is not second


def test_unknown_severity_falls_back_to_class_impact_then_medium():
    ids = frozenset({"sensitive-file-exposure"})
    impacts = {"sensitive-file-exposure": "HIGH"}
    # a known class with a bad severity anchors on the class impact
    f = _finding_from_dict({"where": "u", "category": "Sensitive-File-Exposure", "severity": "WOBBLY"},
                           known_ids=ids, impacts=impacts)
    assert f.severity == "HIGH"
    # an unknown class with a bad severity falls back to MEDIUM
    g = _finding_from_dict({"where": "u", "severity": "WOBBLY"}, known_ids=ids, impacts=impacts)
    assert g.severity == "MEDIUM"


def test_finding_without_a_location_is_dropped():
    assert _finding_from_dict({"severity": "HIGH", "title": "no where"}) is None


def test_category_is_normalized_onto_the_known_class_ids():
    ids = frozenset({"sensitive-file-exposure"})
    f = _finding_from_dict({"where": "u", "category": "Sensitive-File-Exposure", "severity": "medium"},
                           known_ids=ids)
    assert f.data["kind"] == "sensitive-file-exposure"
    assert f.id == "finding:sensitive-file-exposure:u"
    # an unrecognized class collapses to other, so the id stays stable for dedup
    other = _finding_from_dict({"where": "u", "category": "made-up-thing"}, known_ids=ids)
    assert other.data["kind"] == "other"
    assert other.id == "finding:other:u"


def test_nonjson_reply_fails_loud():
    sc = _make(provider=MockProvider(responses=["sorry, I cannot help with that"]))
    with pytest.raises(TriageError):
        sc.triage._judge_chunk("## host x")


def test_missing_findings_key_fails_loud():
    sc = _make(provider=MockProvider(responses=['{"results": []}']))
    with pytest.raises(TriageError):
        sc.triage._judge_chunk("## host x")


def test_findings_not_a_list_fails_loud():
    sc = _make(provider=MockProvider(responses=['{"findings": "nope"}']))
    with pytest.raises(TriageError):
        sc.triage._judge_chunk("## host x")


def test_empty_findings_is_a_clean_result():
    sc = _make(provider=MockProvider(responses=['{"findings": []}']))
    assert sc.triage._judge_chunk("## host x") == []


def test_large_surface_is_split_across_calls():
    # a tiny chunk budget forces the several live hosts to be judged in more than one call,
    # rather than one giant prompt that could overflow and truncate
    sc = _make()
    sc.triage._max_chunk = 40
    run(sc, _seed(), scope=Scope(max_tier="recon", hosts=(ROOT,)), budget=Budget(2000))
    assert len(sc.triage._provider.calls) > 1


def test_knowledge_and_class_ids_ride_the_system_prompt():
    _, sc, _ = _run_capturing()
    system = _knowledge(sc)
    assert "Class id: sensitive-file-exposure" in system
    assert "Sensitive File Exposure" in system


def test_chunk_failure_is_a_degraded_finding_not_a_crash():
    class Broken:
        def complete(self, **kwargs):
            raise RuntimeError("model down")

    sc = _make(provider=Broken())
    report = run(sc, _seed(), scope=Scope(max_tier="recon", hosts=(ROOT,)), budget=Budget(2000))
    # the run still closes, and the failure is a loud finding rather than an uncaught crash
    assert report.closed
    assert any(f.data.get("kind") == "degraded" for f in report.findings)


def test_challenger_drops_a_refuted_finding():
    finder = MockProvider(responses=[_two_findings()])
    # keep the first, refute the second, in finding order
    challenger = MockProvider(responses=['{"refuted": false}', '{"refuted": true, "reason": "login flow"}'])
    sc = _make(provider=finder, challenger=challenger, challenger_model="c")
    out = sc.triage._judge_chunk("## a\nhost a")
    assert [f.where for f in out] == ["https://a/.git/config"]
    # every finding was actually challenged
    assert len(challenger.calls) == 2


def test_challenger_keeps_findings_it_does_not_refute():
    finder = MockProvider(responses=[_two_findings()])
    challenger = MockProvider(default='{"refuted": false}')
    sc = _make(provider=finder, challenger=challenger, challenger_model="c")
    out = sc.triage._judge_chunk("## a\nhost a")
    assert len(out) == 2


def test_judge_overturns_a_refutation():
    finder = MockProvider(responses=[_two_findings()])
    challenger = MockProvider(default='{"refuted": true, "reason": "looks fake"}')
    # the judge keeps the first, drops the second
    judge = MockProvider(responses=['{"keep": true}', '{"keep": false}'])
    sc = _make(provider=finder, challenger=challenger, challenger_model="c",
               judge=judge, judge_model="j")
    out = sc.triage._judge_chunk("## a\nhost a")
    assert [f.where for f in out] == ["https://a/.git/config"]
    assert len(judge.calls) == 2


def test_challenger_failure_keeps_the_finding_recall_safe():
    class BrokenChallenger:
        def complete(self, **kwargs):
            raise RuntimeError("challenger down")

    finder = MockProvider(responses=[_two_findings()])
    sc = _make(provider=finder, challenger=BrokenChallenger(), challenger_model="c")
    # a challenger that errors must not drop findings, recall stays first
    assert len(sc.triage._judge_chunk("## a\nhost a")) == 2


def test_standard_mode_leaves_the_roles_off():
    sc = _make()
    assert sc.triage._challenger is None
    assert sc.triage._judge is None


def test_adversarial_mode_wires_the_roles_from_the_env(monkeypatch):
    monkeypatch.setenv("OPFOR_TRIAGE_MODE", "adversarial")
    monkeypatch.setenv("OPFOR_CHALLENGER_MODEL", "challenger-model")
    sc = _make()
    assert sc.triage._challenger is not None
    assert sc.triage._judge is not None
    assert sc.triage._challenger_model == "challenger-model"


def test_missing_security_headers_are_surfaced_and_the_class_is_selected():
    # the fixture hosts set no security headers, so the posture line lists them all as not set
    # and the knowledge class is selected by the trigger the line carries, so the judge is
    # asked to weigh the omission rather than a keyword rule deciding in code
    _, sc, _ = _run_capturing()
    prompt = _prompt(sc)
    assert "security response headers set: none" in prompt
    assert "not set: strict-transport-security" in prompt
    assert "Missing Security Response Header" in _knowledge(sc)


def test_render_lists_present_security_headers_as_set_and_omits_them_from_missing():
    from opfor.core import Fact
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData, HTTP as HTTPData
    from opfor.scenarios.attacksurface.render import SurfaceRenderer

    world = World()
    world.add(Node(id="domain:h.example.com", type="domain",
                   payload=DomainData(name="h.example.com", root="example.com", source="hint")))
    world.absorb((Fact(kind="http", about="domain:h.example.com",
                       payload=HTTPData(alive=True, status=200, url="https://h.example.com/",
                                        headers=(("strict-transport-security", "max-age=31536000"),
                                                 ("x-frame-options", "DENY")))),))
    text = "\n".join(SurfaceRenderer([], []).units(world))
    assert "security response headers set: strict-transport-security, x-frame-options" in text
    # a header that is set is never listed as missing
    assert "not set: content-security-policy, x-content-type-options, referrer-policy, permissions-policy" in text


def test_directory_listing_body_raises_the_exposure_clue():
    from opfor.scenarios.attacksurface.assets.domain import KNOWLEDGE
    from opfor.scenarios.attacksurface.assets.domain.types import Endpoint
    from opfor.scenarios.attacksurface.render import SurfaceRenderer
    from opfor.scenarios.attacksurface.lifecycle.triage import _load_clues

    clues = _load_clues(KNOWLEDGE / "exposures.yaml")
    renderer = SurfaceRenderer(clues, [])
    # a parent directory the permutation probed that answers with an autoindex listing
    endpoint = Endpoint(url="https://h.example.com/uploads/", path="/uploads/", status=200,
                        content_type="text/html", body="<title>index of /uploads</title>")
    assert any("directory-listing" in clue for clue in renderer._exposure_clues(endpoint))


def test_path_permutation_runs_between_harvest_and_endpoints_without_deadlock():
    from opfor.core.result import CLOSED

    report, _, world = _run_capturing()
    # the permutation barrier released, so every live host carries the marker and the run closed
    live = [n for n in world.nodes("domain")
            if (h := world.latest("http", n.id)) is not None and h.payload.alive]
    assert live and all(world.latest("path_permuted", n.id) is not None for n in live)
    assert report.status == CLOSED


def test_port_scan_is_gated_behind_the_probe_tier():
    from opfor.core import Scope

    # recon tier: the scan is a probe-tier act, so scope retires it unauthorized and no host
    # carries a ports fact, a default run never port-scans
    _, _, recon = _run_capturing(scope=Scope(max_tier="recon", hosts=(ROOT,)))
    assert all(recon.latest("ports", n.id) is None for n in recon.nodes("domain"))

    # probe tier: the operator opted in, so each resolvable host is scanned and carries the fact
    _, _, probe = _run_capturing(scope=Scope(max_tier="probe", hosts=(ROOT,)))
    resolvable = [n for n in probe.nodes("domain")
                  if (r := probe.latest("resolved", n.id)) is not None and r.payload.resolvable]
    assert resolvable and any(probe.latest("ports", n.id) is not None for n in resolvable)


def test_exposed_service_ports_are_surfaced_and_the_class_is_selected():
    from opfor.core import Scope

    def ports(name, addresses=()):
        return {"reachable": True, "scanned": 24,
                "open": [{"port": 6379, "service": "redis", "banner": ""}]}

    _, sc, _ = _run_capturing(scope=Scope(max_tier="probe", hosts=(ROOT,)), ports_fn=ports)
    prompt = _prompt(sc)
    assert "exposed service ports: 6379 redis" in prompt
    assert "Exposed Backend Or Management Service" in _knowledge(sc)


def test_render_shows_exposed_ports_even_on_a_host_without_a_website():
    from opfor.core import Fact
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData, OpenPort, PortScan
    from opfor.scenarios.attacksurface.render import SurfaceRenderer

    # no http fact, so this backend host serves no website, yet its open ports must be judged
    world = World()
    world.add(Node(id="domain:db.example.com", type="domain",
                   payload=DomainData(name="db.example.com", root="example.com", source="permuted")))
    world.absorb((Fact(kind="ports", about="domain:db.example.com",
                       payload=PortScan(host="db.example.com", reachable=True, scanned=24,
                                        open_ports=(OpenPort(port=22, service="ssh",
                                                             banner="SSH-2.0-OpenSSH_8.9"),
                                                    OpenPort(port=6379, service="redis")))),))
    text = "\n".join(SurfaceRenderer([], []).units(world))
    assert "exposed service ports: 22 ssh (banner: SSH-2.0-OpenSSH_8.9); 6379 redis" in text


def test_tls_posture_is_probed_on_live_hosts_and_surfaced_for_the_judge():
    _, sc, world = _run_capturing()
    live = [n for n in world.nodes("domain")
            if (h := world.latest("http", n.id)) is not None and h.payload.alive]
    # every live host carries a tls fact, since the TLS probe runs on hosts that answered HTTP
    assert live and all(world.latest("tls", n.id) is not None for n in live)
    prompt = _prompt(sc)
    assert "TLS certificate: valid" in prompt
    assert "TLS Certificate Hygiene" in _knowledge(sc)


def test_render_shows_an_invalid_tls_certificate_with_its_reason():
    from opfor.core import Fact
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData, HTTP as HTTPData, TLSPosture
    from opfor.scenarios.attacksurface.render import SurfaceRenderer

    world = World()
    world.add(Node(id="domain:h.example.com", type="domain",
                   payload=DomainData(name="h.example.com", root="example.com", source="hint")))
    world.absorb((
        Fact(kind="http", about="domain:h.example.com",
             payload=HTTPData(alive=True, status=200, url="https://h.example.com/")),
        Fact(kind="tls", about="domain:h.example.com",
             payload=TLSPosture(host="h.example.com", reachable=True, valid=False,
                                validity_error="certificate has expired", protocol="TLSv1.2")),
    ))
    text = "\n".join(SurfaceRenderer([], []).units(world))
    assert "TLS certificate: INVALID, certificate has expired; protocol TLSv1.2" in text


def test_insecure_cookie_flags_are_surfaced_and_the_class_is_selected():
    # a session cookie set without Secure or HttpOnly, added to whichever hosts the fixture
    # already reports alive, so aliveness is unchanged and only the cookie posture is new
    def probe(name, addresses=()):
        result = _probe(name, addresses)
        if result.get("alive"):
            return {**result, "headers": (("set-cookie", "sid; Path=/"),)}
        return result

    _, sc, _ = _run_capturing(probe_fn=probe)
    prompt = _prompt(sc)
    assert "set-cookie: sid; Path=/" in prompt
    assert "Insecure Cookie Flags" in _knowledge(sc)


def test_dns_email_posture_is_read_on_roots_only_and_surfaced_for_the_judge():
    _, sc, world = _run_capturing()
    # the root carries the posture fact, and email authentication is a root property, so a
    # discovered subdomain is never given the fact
    assert world.latest("dns_email", "domain:example.com") is not None
    for node in world.nodes("domain"):
        if node.payload.name != node.payload.root:
            assert world.latest("dns_email", node.id) is None
    prompt = _prompt(sc)
    assert "email/DNS security: SPF absent" in prompt
    assert "Weak Email Authentication" in _knowledge(sc)


def test_render_shows_a_configured_root_email_and_dns_posture_even_without_a_website():
    from opfor.core import Fact
    from opfor.scenarios.attacksurface.assets.domain.types import DNSEmailPosture, DomainData
    from opfor.scenarios.attacksurface.render import SurfaceRenderer

    # no http fact, so the root serves no website, yet the email posture must still be judged
    world = World()
    world.add(Node(id="domain:example.com", type="domain",
                   payload=DomainData(name="example.com", root="example.com", source="hint")))
    world.absorb((Fact(kind="dns_email", about="domain:example.com",
                       payload=DNSEmailPosture(domain="example.com", spf=("v=spf1 -all",),
                                               dmarc="v=DMARC1; p=reject",
                                               caa=('0 issue "letsencrypt.org"',), dnssec=True)),))
    text = "\n".join(SurfaceRenderer([], []).units(world))
    assert ("email/DNS security: SPF v=spf1 -all; DMARC v=DMARC1; p=reject; "
            "DNSSEC validated; CAA 1 record(s)") in text


def test_system_prompts_frame_target_text_as_untrusted():
    from opfor.scenarios.attacksurface.lifecycle import confirm as confirm_mod
    from opfor.scenarios.attacksurface.lifecycle import triage as triage_mod
    # target-controlled surface text is embedded in every model prompt, so each prompt must
    # frame it as untrusted data whose embedded instructions are the attack, not guidance
    assert "untrusted" in triage_mod.SYSTEM.lower()
    assert "untrusted" in triage_mod.CHALLENGER_SYSTEM.lower()
    assert "untrusted" in triage_mod.JUDGE_SYSTEM.lower()
    assert "untrusted" in confirm_mod.SYSTEM.lower()


def test_malformed_findings_are_dropped_loudly_with_a_degraded_marker():
    import json

    from opfor.core import MockProvider
    from opfor.scenarios.attacksurface.lifecycle.triage import SurfaceTriage

    reply = json.dumps({"findings": [
        {"category": "sensitive-file-exposure", "title": "ok", "severity": "HIGH",
         "where": "https://h/a"},
        {"category": "x"},          # no location, dropped
        "not-an-object",            # not a dict, dropped
    ]})
    triage = SurfaceTriage([], provider=MockProvider(responses=[reply]), model="m")
    found = triage._judge_chunk("## some host block")
    # the two malformed entries do not vanish silently, a degraded marker says so
    degraded = [f for f in found if f.data.get("kind") == "triage_degraded"]
    assert degraded and degraded[0].data["dropped"] == 2
    assert degraded[0].severity == "INFO"
    # the well-formed finding still comes through
    assert any(f.where == "https://h/a" for f in found)


def test_confidence_is_coerced_to_a_float_or_none():
    from opfor.scenarios.attacksurface.lifecycle.triage import _confidence
    # a string, a null, or an out-of-range value never lands raw in the structured axes
    assert _confidence("high") is None
    assert _confidence(None) is None
    assert _confidence(1.5) == 1.0
    assert _confidence(0.7) == 0.7


def test_dedup_keeps_two_distinct_titles_at_one_location():
    from opfor.core.result import Finding
    from opfor.scenarios.attacksurface.lifecycle.triage import SurfaceTriage
    a = Finding(id="finding:known-vulnerability:h", title="CVE-1", severity="HIGH", where="h")
    b = Finding(id="finding:known-vulnerability:h", title="CVE-2", severity="HIGH", where="h")
    dup = Finding(id="finding:known-vulnerability:h", title="CVE-1", severity="HIGH", where="h")
    out = SurfaceTriage._dedup([a, b, dup])
    # two genuinely distinct issues of one class at one location both survive, the exact
    # duplicate is dropped
    assert len(out) == 2 and {f.title for f in out} == {"CVE-1", "CVE-2"}

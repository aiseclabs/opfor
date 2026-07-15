from __future__ import annotations

import json

import pytest

from opfor.core import Budget, MockProvider, Node, Phase, Scope, World, run
from opfor.core.result import CLOSED
from opfor.scenarios.attacksurface import build
from opfor.scenarios.attacksurface.triage import TriageError, _finding_from_dict
from opfor.scenarios.attacksurface.types import Org

from tests.surface_fixtures import *


def test_report_prints_the_poc_and_evidence(capsys):
    from opfor import cli
    from opfor.core.phase import Phase
    from opfor.core.result import CLOSED, Finding, Report

    report = Report(
        scenario="attacksurface", status=CLOSED, reached=Phase.TRIAGE, terminal=Phase.TRIAGE,
        findings=(Finding(id="f1", title="Exposed .git", severity="HIGH",
                          where="https://x.example.com/.git/config",
                          evidence="the response is a git config",
                          poc="curl -s https://x.example.com/.git/config"),),
        notes=())
    cli._print_report(report)
    out = capsys.readouterr().out
    # the safe, reproducible command and its evidence ride the report, so an operator can
    # confirm the finding by hand
    assert "poc: curl -s https://x.example.com/.git/config" in out
    assert "evidence: the response is a git config" in out


def test_default_run_stays_at_triage_and_reproduces_nothing():
    """The reproduce phase is opt-in, so a default run closes at TRIAGE and records no
    reproduction, the regression guard that the new phase changes nothing by default."""
    report, _scenario, world = _run_capturing()
    assert report.reached == Phase.TRIAGE
    assert report.terminal == Phase.TRIAGE
    assert world.facts("reproduction") == ()


def test_reproduce_build_raises_terminal_to_exploit_and_registers_the_capability():
    reproducing = _make(reproduce=True)
    assert reproducing.terminal == Phase.EXPLOIT
    assert any(cap.name == "reproduce_finding" for cap in reproducing.capabilities)
    assert _make().terminal == Phase.TRIAGE


def test_engine_reproduces_a_grounded_finding_in_exploit_when_authorized():
    """End to end through the real engine: with reproduce opted in and the intrusive tier
    authorized, the EXPLOIT phase replays a grounded finding's GET and records the receipt."""
    from opfor.scenarios.attacksurface.reproduce import FindingClaim, PoCRequest

    fetched = []

    def fetch(url):
        fetched.append(url)
        return {"status": 200, "url": url, "content_type": "application/json", "body": "{}"}

    world = _seed()
    world.add(Node(id="finding:x", type="finding", payload=FindingClaim(
        finding_id="finding:x", title="open spec", severity="HIGH",
        where="https://www.example.com/openapi.json",
        request=PoCRequest(method="GET", url="https://www.example.com/openapi.json",
                           expect="HTTP 200 application/json", source="endpoint:seed"))))
    scenario = _make(reproduce=True, reproduce_fetch_fn=fetch)
    scope = Scope(max_tier="intrusive", hosts=(ROOT,), authorized=True)
    report = run(scenario, world, scope=scope, budget=Budget(2000))

    assert report.closed and report.reached == Phase.EXPLOIT
    assert fetched == ["https://www.example.com/openapi.json"]
    repro = {f.about: f.payload for f in world.facts("reproduction")}
    assert repro["finding:x"].status == 200


def test_engine_denies_reproduce_without_authorization_and_stays_loud():
    """Same run without the recorded authorization: the reproduce task is scope-denied and
    the fetch is never sent, deny-by-default holds even with the phase enabled."""
    from opfor.scenarios.attacksurface.reproduce import FindingClaim, PoCRequest

    fetched = []
    world = _seed()
    world.add(Node(id="finding:x", type="finding", payload=FindingClaim(
        finding_id="finding:x", title="open spec", severity="HIGH",
        where="https://www.example.com/openapi.json",
        request=PoCRequest(method="GET", url="https://www.example.com/openapi.json"))))
    scenario = _make(reproduce=True, reproduce_fetch_fn=lambda url: fetched.append(url))
    scope = Scope(max_tier="intrusive", hosts=(ROOT,), authorized=False)
    run(scenario, world, scope=scope, budget=Budget(2000))
    assert fetched == []
    assert world.facts("reproduction") == ()


def test_reproduce_replays_a_grounded_get_and_records_the_receipt():
    from opfor.core import Node, Task, World
    from opfor.scenarios.attacksurface.reproduce import (
        FindingClaim, PoCRequest, ReproduceFinding)

    calls = []

    def fetch(url):
        calls.append(url)
        return {"status": 200, "url": url, "content_type": "application/json",
                "body": '{"ok": true}'}

    world = World()
    fid = "finding:api-spec:https://api.example.com/config/all"
    world.add(Node(id=fid, type="finding", payload=FindingClaim(
        finding_id=fid, title="open config", severity="HIGH",
        where="https://api.example.com/config/all",
        request=PoCRequest(method="GET", url="https://api.example.com/config/all",
                           expect="HTTP 200 application/json", source="endpoint:x"))))

    out = ReproduceFinding(fetch).run(Task(capability="reproduce_finding", node=fid), world)
    assert calls == ["https://api.example.com/config/all"]
    repro = out.facts[0].payload
    assert repro.status == 200 and repro.content_type == "application/json"
    assert repro.method == "GET" and repro.error == ""


def test_reproduce_refuses_a_non_read_method_loud():
    from opfor.core import Node, Task, World
    from opfor.scenarios.attacksurface.reproduce import (
        FindingClaim, PoCRequest, ReproduceFinding)
    from opfor.core.capability import Failed

    sent = []
    world = World()
    fid = "finding:x"
    world.add(Node(id=fid, type="finding", payload=FindingClaim(
        finding_id=fid, title="t", severity="HIGH", where="https://h/x",
        request=PoCRequest(method="POST", url="https://h/x"))))
    out = ReproduceFinding(lambda url: sent.append(url)).run(
        Task(capability="reproduce_finding", node=fid), world)
    assert isinstance(out, Failed)
    assert "non-read method" in out.reason
    assert sent == []  # a write is never sent


def test_reproduce_scrubs_secrets_from_the_receipt_body():
    from opfor.scenarios.attacksurface.reproduce import scrub

    assert "[REDACTED]" in scrub('{"api_key": "sk-live-abcdef123456"}')
    assert "sk-live-abcdef123456" not in scrub('{"api_key": "sk-live-abcdef123456"}')
    assert "[REDACTED]" in scrub("Authorization: Bearer eyJhbGciOi.payload.sig")


def test_reproduce_rule_only_targets_grounded_finding_nodes_not_yet_reproduced():
    from opfor.core import Fact, Node, World
    from opfor.scenarios.attacksurface.reproduce import (
        FindingClaim, PoCRequest, Reproduction, reproduce_rule)

    world = World()
    world.add(Node(id="finding:a", type="finding", payload=FindingClaim(
        finding_id="finding:a", title="a", severity="HIGH", where="https://h/a",
        request=PoCRequest(method="GET", url="https://h/a"))))
    world.add(Node(id="finding:b", type="finding", payload=FindingClaim(
        finding_id="finding:b", title="b", severity="HIGH", where="https://h/b",
        request=PoCRequest(method="GET", url="https://h/b"))))
    world.absorb([Fact(kind="reproduction", about="finding:b",
                       payload=Reproduction(method="GET", url="https://h/b", status=200))])

    tasks = reproduce_rule(world)
    ids = {t.node for t in tasks}
    assert ids == {"finding:a"}  # b already reproduced, so it is not re-proposed
    assert tasks[0].scope_host == "h"


def test_reproduce_is_intrusive_and_denied_without_authorization():
    """The reproduce capability is intrusive tier, so scope denies it loud unless the run
    carries the recorded authorization, the deny-by-default envelope the design requires."""
    from opfor.scenarios.attacksurface.reproduce import ReproduceFinding
    from opfor.core.scope import Scope

    cap = ReproduceFinding(lambda url: {})
    assert cap.tier == "intrusive" and cap.osint is False
    denied = Scope(max_tier="intrusive", hosts=("example.com",), authorized=False).authorize(
        cap.tier, osint=cap.osint, host="api.example.com")
    assert not denied.allowed
    allowed = Scope(max_tier="intrusive", hosts=("example.com",), authorized=True).authorize(
        cap.tier, osint=cap.osint, host="api.example.com")
    assert allowed.allowed


def test_confirm_build_raises_terminal_to_confirm_and_wires_the_judge():
    confirming = _make(confirm=True)
    assert confirming.terminal == Phase.CONFIRM
    assert confirming.confirm is not None
    # confirm implies reproduce, since it regrades the reproduction receipts
    assert any(cap.name == "reproduce_finding" for cap in confirming.capabilities)
    assert _make().confirm is None and _make().terminal == Phase.TRIAGE


def test_confirm_regrades_a_finding_against_its_receipt():
    """A finding with a live receipt is regraded on what the request returned, the verdict,
    the reason, and the receipt ride the finding for the report."""
    from opfor.core import Fact, World
    from opfor.scenarios.attacksurface.confirm import ConfirmTriage

    world = World()
    world.absorb([Fact(kind="reproduction", about="finding:a",
                       payload=_receipt(content_type="text/html", excerpt="<!doctype html>"))])
    reply = json.dumps({"verdict": "weakened", "severity": "LOW",
                        "reason": "the app returned an html shell, not a raw config"})
    confirm = ConfirmTriage(provider=MockProvider(responses=[reply]), model="m")

    out = confirm.reconfirm(world, (_claim("finding:a", severity="MEDIUM"),))
    assert len(out) == 1
    assert out[0].severity == "LOW"  # regraded down on the receipt
    assert out[0].data["reproduction_verdict"] == "weakened"
    assert "html shell" in out[0].data["reproduction_reason"]
    assert out[0].data["receipt"]["content_type"] == "text/html"


def test_confirm_passes_through_a_finding_with_no_receipt_unchanged():
    """A finding the reproduce phase never replayed carries no receipt, so confirm returns it
    untouched and never invents a verdict for it."""
    from opfor.core import World
    from opfor.scenarios.attacksurface.confirm import ConfirmTriage

    provider = MockProvider(default='{"verdict": "confirmed", "severity": "HIGH"}')
    confirm = ConfirmTriage(provider=provider, model="m")
    out = confirm.reconfirm(World(), (_claim("finding:a", severity="MEDIUM"),))
    assert out[0].severity == "MEDIUM"
    assert "reproduction_verdict" not in out[0].data
    assert provider.calls == []  # the model is never asked about a finding with no receipt


def test_confirm_binds_a_receipt_by_url_not_by_a_shared_id():
    """Two distinct findings can share an id, two CVEs on one host, but only one materializes a
    claim node and a receipt. Confirm must regrade only the finding whose grounded request the
    receipt actually replayed, never the co-id finding against a request it never made."""
    from opfor.core import Fact, World
    from opfor.scenarios.attacksurface.confirm import ConfirmTriage

    world = World()
    # the single receipt replayed /a, the request the first finding was grounded on
    world.absorb([Fact(kind="reproduction", about="finding:known-vulnerability:h",
                       payload=_receipt(url="https://h/a"))])
    reply = json.dumps({"verdict": "confirmed", "severity": "HIGH", "reason": "reachable"})
    confirm = ConfirmTriage(provider=MockProvider(responses=[reply]), model="m")

    graded = _claim("finding:known-vulnerability:h", where="https://h/a", title="CVE-1")
    other = _claim("finding:known-vulnerability:h", where="https://h/b", title="CVE-2")
    out = confirm.reconfirm(world, (graded, other))

    by_title = {f.title: f for f in out}
    # the finding grounded on /a is regraded against its receipt
    assert by_title["CVE-1"].data["reproduction_verdict"] == "confirmed"
    # the co-id finding grounded on /b is left as judged, not confirmed against /a's receipt
    assert "reproduction_verdict" not in by_title["CVE-2"].data


def test_confirm_is_loud_when_the_model_reply_cannot_be_parsed():
    """A confirm call that returns no verdict is a failed confirmation, not a silent pass. The
    finding is kept at its judged severity and marked confirm-failed, invariant 5."""
    from opfor.core import Fact, World
    from opfor.scenarios.attacksurface.confirm import ConfirmTriage

    world = World()
    world.absorb([Fact(kind="reproduction", about="finding:a", payload=_receipt())])
    confirm = ConfirmTriage(provider=MockProvider(default="not json at all"), model="m")
    out = confirm.reconfirm(world, (_claim("finding:a", severity="HIGH"),))
    assert out[0].severity == "HIGH"  # never silently downgraded on a failed call
    assert out[0].data["reproduction_verdict"] == "confirm-failed"
    assert "failed" in out[0].data["reproduction_reason"]


def test_confirm_regrades_end_to_end_across_triage_reproduce_and_confirm():
    """The whole intrusive spine wired by hand: triage grounds a finding and materializes its
    node, reproduce records the live receipt, confirm regrades the finding on that receipt."""
    from opfor.core import Fact, Node, Task, World
    from opfor.scenarios.attacksurface.classes.domain.types import DomainData, Endpoint, Resolved
    from opfor.scenarios.attacksurface.confirm import ConfirmTriage
    from opfor.scenarios.attacksurface.grounding import FindingGrounder
    from opfor.scenarios.attacksurface.reproduce import ReproduceFinding
    from opfor.scenarios.attacksurface.triage import SurfaceTriage

    world = World()
    world.add(Node(id="domain:api.example.com", type="domain",
                   payload=DomainData(name="api.example.com", root="example.com", source="crt")))
    # resolve the host so the resolution caveat does not suppress the model judgment
    world.absorb([Fact(kind="resolved", about="domain:api.example.com",
                       payload=Resolved(resolvable=True, addresses=("192.0.2.1",)))])
    ep_id = "endpoint:api.example.com/.env"
    world.add(Node(id=ep_id, type="endpoint",
                   payload=Endpoint(url="https://api.example.com/.env", path="/.env",
                                    status=200, auth_required=False, content_type="text/html")))

    finder = json.dumps({"findings": [{
        "category": "sensitive-file-exposure", "title": "Exposed .env", "severity": "MEDIUM",
        "where": "https://api.example.com/.env", "evidence": "a dotenv path answered 200",
        "poc": "safe read: curl -s https://api.example.com/.env", "confidence": 0.8}]})
    triage = SurfaceTriage([], provider=MockProvider(responses=[finder]), model="m")
    # the engine runs TRIAGE then the post-triage grounder, so mirror both here, grounding is
    # no longer inside judge
    findings = tuple(FindingGrounder().run(world, tuple(triage.judge(world))))
    # no knowledge dirs are loaded here, so the model category normalizes to "other", the
    # finding is still grounded against the observed endpoint GET and materialized as a node
    graded = [f for f in findings if f.where == "https://api.example.com/.env"]
    assert graded and "poc_request" in graded[0].data  # grounded, so a node was materialized

    def fetch(url):
        return {"status": 200, "url": url, "content_type": "text/html",
                "body": "<!doctype html><html>app shell</html>"}

    outcome = ReproduceFinding(fetch).run(
        Task(capability="reproduce_finding", node=graded[0].id), world)
    world.absorb(outcome.facts)  # the engine absorbs a capability's facts, so mirror it here

    verdict = json.dumps({"verdict": "refuted", "severity": "INFO",
                          "reason": "the receipt is the spa html shell, not a dotenv file"})
    confirm = ConfirmTriage(provider=MockProvider(responses=[verdict]), model="m")
    out = confirm.reconfirm(world, tuple(findings))
    regraded = next(f for f in out if f.id == graded[0].id)
    assert regraded.severity == "INFO"  # the false positive is graded down on the live receipt
    assert regraded.data["reproduction_verdict"] == "refuted"


def test_engine_reaches_the_confirm_phase_when_opted_in_and_authorized():
    """End to end through the real engine: with confirm opted in and the intrusive tier
    authorized, the run advances through EXPLOIT and closes at CONFIRM."""
    scenario = _make(confirm=True)
    scope = Scope(max_tier="intrusive", hosts=(ROOT,), authorized=True)
    report = run(scenario, _seed(), scope=scope, budget=Budget(2000))
    assert report.closed and report.reached == Phase.CONFIRM


def test_regression_surface_closes_at_confirm_with_code_minted_findings():
    """The full spine over the synthetic surface closes at CONFIRM, and the findings that do
    not depend on the model, an associated root, a wildcard blind spot, a github org, are
    minted deterministically. A model-backed judgment is empty here by design, the default
    provider returns no findings, so only the code-minted structural findings remain."""
    world = _seed()
    scenario = _make(confirm=True, reproduce_fetch_fn=_read_only)
    scope = Scope(max_tier="intrusive", hosts=(ROOT,), authorized=True)
    report = run(scenario, world, scope=scope, budget=Budget(3000))

    assert report.closed and report.reached == Phase.CONFIRM
    ids = {f.id for f in report.findings}
    assert "finding:root:example.net" in ids
    assert "finding:blindspot:wildcard" in ids
    assert "finding:github_org:examplecorp" in ids
    # reproduce is read only: any receipt recorded came from a safe method, never a write
    for fact in world.facts("reproduction"):
        assert fact.payload.method in ("GET", "HEAD", "OPTIONS")


def test_regression_a_grounded_finding_replays_exactly_its_observed_get_read_only():
    """A model finding grounded in an observed GET materializes a poc_request, and the EXPLOIT
    phase replays exactly that request and nothing else, read only. This locks the grounding
    and read-only invariants end to end through the engine, independent of what the model
    judged, since the finding is canned."""
    finding = json.dumps({"findings": [{
        "category": "api-spec-exposure", "title": "Open spec", "severity": "MEDIUM",
        "where": "https://spa.example.com/", "evidence": "the spec is reachable",
        "poc": "safe read: curl -s https://spa.example.com/", "confidence": 0.8}]})
    fetched: list[str] = []

    def repro_fetch(url):
        fetched.append(url)
        return {"status": 200, "url": url, "content_type": "text/html", "body": "<html>spa</html>"}

    world = _seed()
    scenario = _make(reproduce=True, provider=MockProvider(default=finding),
                     reproduce_fetch_fn=repro_fetch)
    scope = Scope(max_tier="intrusive", hosts=(ROOT,), authorized=True)
    report = run(scenario, world, scope=scope, budget=Budget(3000))

    assert report.reached == Phase.EXPLOIT
    spec = next((f for f in report.findings if f.where == "https://spa.example.com/"), None)
    assert spec is not None
    request = spec.data.get("poc_request")
    assert request is not None and request["method"] == "GET"
    # grounding integrity: the request traces to a recorded observation, not model prose
    assert request["source"].split(":")[0] in ("http", "endpoint", "spec_audit")
    # the EXPLOIT phase replayed exactly the grounded GET and nothing else
    assert fetched == ["https://spa.example.com/"]
    receipts = [fact.payload for fact in world.facts("reproduction") if fact.about == spec.id]
    assert len(receipts) == 1 and receipts[0].method == "GET" and receipts[0].status == 200


def test_regression_grounding_never_replays_an_unobserved_url():
    """A model finding whose safe-read poc names a URL the surface never observed is not
    grounded, so no node is materialized and the EXPLOIT phase replays nothing. This locks
    strict grounding: reproduce touches only requests a capability already made."""
    finding = json.dumps({"findings": [{
        "category": "sensitive-file-exposure", "title": "Invented path", "severity": "HIGH",
        "where": "https://spa.example.com/", "evidence": "claims a path that was never probed",
        "poc": "safe read: curl -s https://spa.example.com/this-was-never-observed",
        "confidence": 0.9}]})
    fetched: list[str] = []

    def repro_fetch(url):
        fetched.append(url)
        return {"status": 200, "url": url, "content_type": "text/html", "body": ""}

    world = _seed()
    scenario = _make(reproduce=True, provider=MockProvider(default=finding),
                     reproduce_fetch_fn=repro_fetch)
    scope = Scope(max_tier="intrusive", hosts=(ROOT,), authorized=True)
    report = run(scenario, world, scope=scope, budget=Budget(3000))

    invented = next((f for f in report.findings if f.title == "Invented path"), None)
    assert invented is not None
    assert "poc_request" not in invented.data  # never grounded on an unobserved url
    assert fetched == []  # so the EXPLOIT phase replayed nothing


def test_reproduce_records_a_redirect_raw_with_location_and_expect():
    from opfor.core import Node, Task, World
    from opfor.scenarios.attacksurface.reproduce import FindingClaim, PoCRequest, ReproduceFinding

    world = World()
    world.add(Node(id="finding:x", type="finding", payload=FindingClaim(
        finding_id="finding:x", title="Open panel", severity="HIGH", where="https://h/panel",
        request=PoCRequest(method="GET", url="https://h/panel", expect="HTTP 200 text/html"))))

    def fetch(url):
        # a live redirect, which a following fetch would chase off-site, is captured raw
        return {"status": 302, "url": url, "content_type": "text/html",
                "location": "https://accounts.google.com/login", "body": "redirecting"}

    outcome = ReproduceFinding(fetch).run(
        Task(capability="reproduce_finding", node="finding:x"), world)
    repro = outcome.facts[0].payload
    # the 302 stays a 302, not a followed 200, and its location and the grounded expect ride
    # the receipt so confirm can tell a login redirect from an open resource
    assert repro.status == 302
    assert repro.location == "https://accounts.google.com/login"
    assert repro.expect == "HTTP 200 text/html"


def test_readonly_fetch_uses_a_non_following_redirect_handler():
    from opfor.scenarios.attacksurface.classes.domain.http import _NoRedirect
    # returning None from redirect_request means a 3xx is returned raw rather than chased, so
    # the reproduce replay never follows a server-controlled redirect off-scope or into a GET
    # side effect
    handler = _NoRedirect()
    assert handler.redirect_request(None, None, 302, "Found", {}, "https://evil/") is None

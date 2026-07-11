"""attack-surface: an org name expands into ranked assets, driven by fake seams.

Fixtures use the reserved example domain from RFC 2606, so no real target is named in
the code and nothing here touches a live endpoint. Triage is model-driven, so a
MockProvider stands in for the model. The deterministic contract the tests hold triage
to is what it puts in front of the model, the surface it renders and the knowledge it
selects, and how it maps the reply, never a hardcoded verdict, since the verdict is the
model's.
"""

from __future__ import annotations

import json

import pytest

from opfor.core import Budget, MockProvider, Node, Phase, Scope, World, run
from opfor.core.result import CLOSED
from opfor.scenarios.attacksurface import build
from opfor.scenarios.attacksurface.triage import TriageError, _finding_from_dict
from opfor.scenarios.attacksurface.types import Org

ROOT = "example.com"

# Certificate transparency result for the hint root. api.example.com is a real host whose
# only interface is named by a script on admin.example.com, so it proves cross-host harvest.
CRT = {ROOT: {"www.example.com", "admin.example.com", "old.example.com", "cdn.example.com",
              "spa.example.com", "cf.example.com", "api.example.com",
              # a wildcard cert, its individual hosts are hidden from certificate transparency
              "*.dev.example.com"}}

# DNS per name, a name absent here is unresolvable. old.example.com is dangling.
DNS = {
    "example.com": {"resolvable": True, "addresses": ("1.1.1.1",)},
    "www.example.com": {"resolvable": True, "addresses": ("1.1.1.2",)},
    "admin.example.com": {"resolvable": True, "addresses": ("1.1.1.3",)},
    "cdn.example.com": {"resolvable": True, "addresses": ("1.1.1.4",)},
    "spa.example.com": {"resolvable": True, "addresses": ("1.1.1.5",)},
    "cf.example.com": {"resolvable": True, "addresses": ("1.1.1.6",)},
    "api.example.com": {"resolvable": True, "addresses": ("1.1.1.7",)},
    # the wildcard base resolves but serves nothing, so it stays quiet in the surface
    "dev.example.com": {"resolvable": True, "addresses": ("1.1.1.8",)},
    # dangling: answers a CNAME to an unclaimed target but no address, the takeover signal
    "old.example.com": {"resolvable": False, "addresses": (),
                        "cnames": ("old-app.herokuapp.com",)},
}

# HTTP per name. cdn points at an unclaimed bucket, admin is a live admin surface, spa is
# a single-page app that answers 200 for every path.
HTTP = {
    "example.com": {"alive": True, "status": 200, "url": "https://example.com/", "server": "nginx",
                    "title": "home", "body": "welcome"},
    "www.example.com": {"alive": True, "status": 200, "url": "https://www.example.com/", "server": "nginx",
                        "title": "home", "body": "welcome"},
    "admin.example.com": {"alive": True, "status": 200, "url": "https://admin.example.com/", "server": "nginx",
                          "title": "admin login", "body": "sign in"},
    "cdn.example.com": {"alive": True, "status": 404, "url": "https://cdn.example.com/", "server": "AmazonS3",
                        "title": "", "body": "<html>nosuchbucket</html>"},
    "spa.example.com": {"alive": True, "status": 200, "url": "https://spa.example.com/", "server": "cf",
                        "title": "app", "body": "<html>spa app single page</html>"},
    "cf.example.com": {"alive": True, "status": 200, "url": "https://cf.example.com/", "server": "cf",
                       "title": "app", "body": "<html>cf</html>"},
    "api.example.com": {"alive": True, "status": 200, "url": "https://api.example.com/", "server": "nginx",
                        "title": "api", "body": "ok"},
}

# GitHub search and repos, keyed off the org name.
GH_ORGS = {"ExampleCorp": [{"login": "examplecorp", "url": "https://github.com/examplecorp", "org_id": 7}]}
GH_REPOS = {
    "examplecorp": [
        {"full_name": "examplecorp/web", "url": "u1", "language": "Go", "pushed_at": "2026-06-01", "archived": False},
        {"full_name": "examplecorp/infra", "url": "u2", "language": "HCL", "pushed_at": "2026-05-01", "archived": False},
    ]
}


def _search(name, token=""):
    return list(GH_ORGS.get(name, []))


def _repos(login, token=""):
    return list(GH_REPOS.get(login, []))


# Interface probes per absolute url. Anything absent answers 404 and is skipped.
# /api/secret is only reachable by reading it out of a JavaScript bundle, /legacy only by a
# passive url source, /secret-panel only from robots.txt, so each proves one candidate source.
ENDPOINTS = {
    "https://admin.example.com/.git/config": {"status": 200, "body": "[core]\n\trepositoryformatversion = 0"},
    "https://admin.example.com/.env": {"status": 200, "body": "db_password=secret\napi_key=abc"},
    "https://admin.example.com/metrics": {"status": 401, "body": "unauthorized"},
    "https://admin.example.com/admin": {"status": 200, "body": "admin dashboard overview"},
    "https://admin.example.com/graphql": {"status": 200, "ct": "application/json", "body": '{"data":{}}'},
    "https://admin.example.com/api/secret": {"status": 200, "body": "secret payload"},
    # a login redirect and a refusal body, both reachable but really protected
    "https://admin.example.com/portal": {"status": 302, "loc": "https://admin.example.com/login", "body": ""},
    "https://admin.example.com/private": {"status": 200, "body": "Unauthorized"},
    "https://api.example.com/v2/balance": {"status": 200, "body": "balance"},
    "https://www.example.com/legacy": {"status": 200, "body": "legacy console"},
    "https://example.com/secret-panel": {"status": 200, "body": "hidden panel"},
    "https://example.com/robots.txt": {"status": 200, "body": "user-agent: *\ndisallow: /secret-panel"},
}


def _fetch(name, addresses, path):
    url = f"https://{name}{path}"
    if name == "spa.example.com":
        # a single-page app: 200 HTML for every path, but a real JSON spec at one path
        if path == "/openapi.json":
            return {"status": 200, "url": url, "content_type": "application/json",
                    "server": "cf", "title": "", "body": '{"openapi":"3.0.0","paths":{}}'}
        return {"status": 200, "url": url, "content_type": "text/html",
                "server": "cf", "title": "", "body": "<html>spa app single page</html>"}
    if name == "cf.example.com":
        # a host that serves an empty 200 for /.env, the shape that used to false-positive
        if path == "/.env":
            return {"status": 200, "url": url, "content_type": "", "server": "cf", "title": "", "body": ""}
        return {"status": 404, "url": url, "content_type": "", "server": "", "title": "", "body": ""}
    d = ENDPOINTS.get(url, {"status": 404, "body": ""})
    return {"status": d["status"], "url": url, "content_type": d.get("ct", ""),
            "server": d.get("server", ""), "title": "", "body": d["body"].lower(),
            "location": d.get("loc", "")}


# Certificate-SAN sibling roots per known root. example.com and example.net are bundled
# on one dedicated cert, evidence they share an owner. example.net pivots no further.
SIBLINGS = {ROOT: {"example.net": "shares a certificate with example.com, 2 roots on the cert"}}


def _pivot(domain):
    return dict(SIBLINGS.get(domain, {}))


# Reverse-WHOIS results keyed by search term. The org name resolves to a root registered
# to the same registrant, the definitional ownership signal.
WHOIS = {"ExampleCorp": {"example.org": "registration record names ExampleCorp"}}


def _reverse(term, api_key=""):
    return dict(WHOIS.get(term, {}))


# A full document fetch, the app declaring itself. spa serves an OpenAPI spec, admin serves
# a home page linking a JavaScript bundle that hardcodes an API path only readable from it.
def _fetch_doc(name, path):
    if name == "spa.example.com" and path == "/openapi.json":
        return {"status": 200, "content_type": "application/json",
                "text": '{"openapi":"3.0.0","paths":{"/users":{"get":{}},"/orders":{"get":{},"post":{}}}}'}
    if name == "admin.example.com" and path == "/":
        return {"status": 200, "content_type": "text/html",
                "text": '<html><body><script src="/app.js"></script></body></html>'}
    if name == "admin.example.com" and path == "/app.js":
        return {"status": 200, "content_type": "application/javascript",
                "text": ('const API="/api";fetch("/api/secret");const css="/main.css";'
                         'fetch("/portal");fetch("/private");'
                         'fetch("https://api.example.com/v2/balance");')}
    return {"status": None, "content_type": "", "text": ""}


def _introspect(name, path="/graphql"):
    if name == "admin.example.com":
        return {"__schema": {"queryType": {"name": "Query", "fields": [{"name": "me"}, {"name": "users"}]},
                             "mutationType": {"name": "Mutation", "fields": [{"name": "login"}]}}}
    return None


def _wayback(host):
    return {"/legacy"} if host == "www.example.com" else set()


def _enumerate(domain):
    return set(CRT.get(domain, set()))


def _resolve(name):
    return DNS.get(name, {"resolvable": False, "addresses": ()})


def _probe(name, addresses=()):
    return HTTP.get(name, {"alive": False, "status": None, "url": "", "server": "", "title": "", "body": ""})


def _make(**over):
    """Build the scenario with every seam faked, so no test touches the network or the
    model. A MockProvider stands in for the triage model, returning an empty result by
    default. A test overrides one seam to drive a failure or a variant, or passes its own
    provider to drive a canned model reply."""
    seams = dict(search_fn=_search, repos_fn=_repos, enumerate_fn=_enumerate, pivot_fn=_pivot,
                 resolve_fn=_resolve, probe_fn=_probe, fetch_fn=_fetch, fetch_doc_fn=_fetch_doc,
                 introspect_fn=_introspect, wayback_fn=_wayback)
    seams.update(over)
    seams.setdefault("provider", MockProvider(default='{"findings": []}'))
    seams.setdefault("model", "test-model")
    return build(**seams)


def _scenario():
    return _make()


def _seed(*, domains=(ROOT,), classes=()):
    world = World()
    world.add(Node(id="org:ExampleCorp", type="org",
                   payload=Org(name="ExampleCorp", domains=tuple(domains), classes=tuple(classes))))
    return world


def _run(world, scope=None, budget=500):
    return run(_scenario(), world,
               scope=scope or Scope(max_tier="recon", hosts=(ROOT,)), budget=Budget(budget))


def _run_capturing(world=None, *, scope=None, budget=2000, **over):
    """Run the full pipeline and return the report and the scenario, so a test can read the
    surface prompt the triage model was given off `scenario.triage._provider`."""
    scenario = _make(**over)
    world = world if world is not None else _seed()
    report = run(scenario, world,
                 scope=scope or Scope(max_tier="recon", hosts=(ROOT,)), budget=Budget(budget))
    return report, scenario, world


def _prompt(scenario) -> str:
    """The surface report the triage model received in the user message of its first call."""
    calls = scenario.triage._provider.calls
    assert calls, "the triage model was not called"
    return calls[0]["messages"][0].content


def _knowledge(scenario) -> str:
    """The system prompt of the first call, where the selected knowledge classes ride."""
    calls = scenario.triage._provider.calls
    assert calls, "the triage model was not called"
    return calls[0]["system"]


# --- the run closes and expands assets -------------------------------------------------


def test_run_closes():
    report = _run(_seed())
    assert report.closed
    assert report.status == CLOSED
    assert report.reached == Phase.TRIAGE


def test_expands_both_asset_classes_from_the_org():
    world = _seed()
    _run(world)
    assert {n.payload.name for n in world.nodes("domain")} >= {"www.example.com", "admin.example.com"}
    assert {n.payload.login for n in world.nodes("github_org")} == {"examplecorp"}
    assert len(world.nodes("github_repo")) == 2


# --- what triage surfaces to the model -------------------------------------------------


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


def test_wildcard_certificate_is_reported_as_a_blind_spot():
    # *.dev.example.com hides its hosts from CT, the run must say so rather than look clean
    report = _run(_seed())
    blind = [f for f in report.findings if f.data.get("kind") == "blindspot"]
    assert len(blind) == 1
    assert blind[0].severity == "INFO"
    assert "dev.example.com" in blind[0].data["bases"]


def test_wildcard_base_node_is_flagged():
    from opfor.core import Node, World
    from opfor.scenarios.attacksurface.capabilities import Subdomains
    from opfor.scenarios.attacksurface.types import DomainData, Org

    world = World()
    world.add(Node(id="org:x", type="org", payload=Org(name="X", domains=("example.com",))))
    world.add(Node(id="domain:example.com", type="domain",
                   payload=DomainData(name="example.com", root="example.com", source="hint")))
    cap = Subdomains(lambda root: {"*.dev.example.com", "api.example.com"})
    from opfor.core import Task
    outcome = cap.run(Task(capability="domain_subdomains", node="domain:example.com"), world)
    nodes = {n.payload.name: n.payload for n in outcome.facts[0].yields}
    assert nodes["dev.example.com"].wildcard is True
    assert nodes["api.example.com"].wildcard is False


def test_dangling_cname_target_is_surfaced_for_takeover_judgment():
    # the CNAME target is the most direct takeover evidence, a dangling name pointing at an
    # unclaimed service, so it must reach the model rather than being reduced to a bool
    _, sc, _ = _run_capturing()
    p = _prompt(sc)
    assert "CNAME to old-app.herokuapp.com" in p


def test_resolve_host_keeps_cname_and_asks_both_address_families(monkeypatch):
    import urllib.request

    from opfor.scenarios.attacksurface.sources import domains

    asked = []

    class _Resp:
        def __init__(self, payload):
            self._payload = payload

        def read(self):
            return json.dumps(self._payload).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    # a CNAME to an unclaimed target, answered but with no address, is the dangling case
    def fake_urlopen(request, timeout=0):
        asked.append(request.full_url)
        if "type=A" in request.full_url:
            return _Resp({"Answer": [{"type": 5, "data": "target.s3.amazonaws.com."}]})
        return _Resp({"Answer": []})

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    result = domains.resolve_host("dangling.example.com")
    assert result["resolvable"] is False
    assert result["addresses"] == ()
    assert result["cnames"] == ("target.s3.amazonaws.com",)
    assert any("type=A" in u for u in asked) and any("type=AAAA" in u for u in asked)


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


# --- deterministic machinery the capability owns ---------------------------------------


def test_endpoints_enumerated_and_auth_classified():
    world = _seed()
    _run(world)
    eps = {n.id: n.payload for n in world.nodes("endpoint")}
    assert "endpoint:admin.example.com/.git/config" in eps
    assert eps["endpoint:admin.example.com/metrics"].auth_required is True
    assert eps["endpoint:admin.example.com/.env"].auth_required is False


def test_static_assets_are_never_probed_into_endpoints():
    # admin's script names /main.css, a static asset, so it must not become an endpoint
    world = _seed()
    _run(world)
    assert world.node("endpoint:admin.example.com/main.css") is None


def test_soft_200_host_yields_only_its_real_interface():
    # spa answers 200 for every path, so the catch-all filter must keep only the real spec
    world = _seed()
    _run(world)
    spa = sorted(n.id for n in world.nodes("endpoint") if "spa.example.com" in n.id)
    assert spa == ["endpoint:spa.example.com/openapi.json"]


def test_html_posing_as_swagger_is_not_an_endpoint():
    world = _seed()
    _run(world)
    assert world.node("endpoint:spa.example.com/swagger.json") is None


def test_empty_env_body_yields_no_exposure_clue():
    # a host that serves an empty 200 for /.env has no KEY=value body, so the deterministic
    # clue must not fire, the clue asserts on content, not the path
    from opfor.scenarios.attacksurface.types import Endpoint

    sc = _make()
    empty = Endpoint(url="https://cf.example.com/.env", path="/.env", status=200, body="")
    real = Endpoint(url="https://x/.env", path="/.env", status=200, body="db_password=secret\napi_key=abc")
    assert sc.triage._exposure_clues(empty) == []
    assert any("exposed-env" in c for c in sc.triage._exposure_clues(real))


# --- structural findings triage mints in code ------------------------------------------


def test_github_org_is_info_inventory():
    report = _run(_seed())
    gh = [f for f in report.findings if f.data["kind"] == "github_org"]
    assert gh and gh[0].where == "examplecorp"
    assert gh[0].severity == "INFO"
    assert gh[0].data["repos"] == 2


def test_class_restriction_runs_only_that_class():
    # github only: no domain nodes discovered, no domain findings
    world = _seed(classes=("github",))
    report = _run(world)
    assert report.closed
    assert world.nodes("domain") == ()
    assert world.nodes("github_org")
    assert all(f.data["kind"] == "github_org" for f in report.findings)


def test_http_probe_denied_when_domain_out_of_scope():
    world = _seed()
    report = _run(world, scope=Scope(max_tier="recon", hosts=("other.test",)))
    assert report.closed
    assert not world.has_fact("domain:example.com", "http")
    assert any("denied" in n and "domain_http" in n for n in report.notes)


def test_total_resolution_failure_reports_incomplete_not_dangling():
    # when not one name resolves, the resolver is the problem, so the run must say
    # incomplete rather than call every name dangling
    def none_resolve(name):
        return {"resolvable": False, "addresses": ()}

    scenario = _make(resolve_fn=none_resolve)
    world = _seed(classes=("domain",))
    report = run(scenario, world, scope=Scope(max_tier="recon", hosts=(ROOT,)), budget=Budget(500))
    kinds = {f.data.get("kind") for f in report.findings}
    assert "incomplete" in kinds
    assert "dangling" not in kinds


def test_resolution_failure_suppresses_the_model_call():
    # with the resolver down triage does not ask the model to judge an unreachable surface
    def none_resolve(name):
        return {"resolvable": False, "addresses": ()}

    _, sc, _ = _run_capturing(_seed(classes=("domain",)), resolve_fn=none_resolve)
    assert sc.triage._provider.calls == []


def test_github_search_failure_still_closes():
    def boom(name, token=""):
        raise TimeoutError("github slow")

    scenario = _make(search_fn=boom)
    world = _seed()
    report = run(scenario, world, scope=Scope(max_tier="recon", hosts=(ROOT,)), budget=Budget(500))
    assert report.closed
    # the failure is loud in the report, not only in the ledger
    assert any("failed" in n and "discover_github" in n for n in report.notes)


def test_no_hint_domains_still_closes_via_github():
    # a bare name with no hint domains and the domain class off still closes on github
    world = _seed(domains=(), classes=("github",))
    report = _run(world)
    assert report.closed
    assert world.nodes("domain") == ()
    assert world.nodes("github_org")


# --- the triage model reply, mapping and fail-loud -------------------------------------


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
    assert git[0].data["poc"].startswith("curl")
    assert git[0].data["confidence"] == 0.9


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


# --- the adversarial roles, challenger and judge ---------------------------------------


def _two_findings():
    return json.dumps({"findings": [
        {"category": "sensitive-file-exposure", "title": "Exposed .git", "severity": "HIGH",
         "where": "https://a/.git/config", "evidence": "core section present"},
        {"category": "unauthenticated-interface", "title": "Login redirect", "severity": "INFO",
         "where": "https://a/portal", "evidence": "302 to /login"},
    ]})


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


# --- root discovery, pivots, and their evidence ----------------------------------------


def test_cert_san_pivot_discovers_a_sibling_root_with_evidence():
    world = _seed()
    _run(world)
    net = world.node("domain:example.net")
    assert net is not None
    assert net.payload.root == "example.net"
    assert net.payload.source == "cert-san"
    assert net.payload.confidence == "confirmed"
    assert "shares a certificate" in net.payload.evidence


def test_discovered_root_is_an_info_finding_carrying_its_evidence():
    report = _run(_seed())
    roots = [f for f in report.findings if f.data.get("kind") == "root"]
    assert [f.where for f in roots] == ["example.net"]
    assert roots[0].severity == "INFO"
    assert "shares a certificate" in roots[0].evidence


def test_hint_root_is_not_reported_as_a_discovered_root():
    report = _run(_seed())
    assert "example.com" not in {f.where for f in report.findings if f.data.get("kind") == "root"}


def test_registrable_root_keeps_multi_label_suffixes():
    from opfor.scenarios.attacksurface.sources.domains import registrable_root

    assert registrable_root("api.example.com") == "example.com"
    assert registrable_root("example.com") == "example.com"
    assert registrable_root("a.b.example.co.uk") == "example.co.uk"


def test_shared_certificate_is_not_treated_as_ownership_evidence():
    from opfor.scenarios.attacksurface.sources.domains import sibling_roots_from_issuances

    # a dedicated cert bundling two roots yields the sibling
    dedicated = [{"dns_names": ["example.com", "www.example.net"]}]
    assert sibling_roots_from_issuances(dedicated, "example.com") == {
        "example.net": "shares a certificate with example.com, 2 roots on the cert"
    }
    # a multi-tenant cert bundling many unrelated roots proves nothing, so it is skipped
    shared = [{"dns_names": ["example.com", "a.org", "b.org", "c.org", "d.org", "e.org", "f.org"]}]
    assert sibling_roots_from_issuances(shared, "example.com") == {}


def test_certspotter_token_429_falls_back_to_an_anonymous_walk(monkeypatch):
    import urllib.error
    import urllib.request

    from opfor.scenarios.attacksurface import config
    from opfor.scenarios.attacksurface.sources import domains

    monkeypatch.setattr(config, "certspotter_token", lambda: "spent-token")

    class _Resp:
        def __init__(self, payload):
            self._payload = payload

        def read(self):
            return json.dumps(self._payload).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    # the token walk answers 429 as if its account quota were spent, the anonymous walk
    # answers with records, so the source recovers rather than going blind
    def fake_urlopen(request, timeout=0):
        if request.get_header("Authorization"):
            raise urllib.error.HTTPError(request.full_url, 429, "Too Many Requests", {}, None)
        return _Resp([{"dns_names": ["api.example.com", "www.example.com"]}])

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    assert domains.certspotter_subdomains("example.com") == {"api.example.com", "www.example.com"}


def test_certspotter_token_error_that_is_not_429_is_raised(monkeypatch):
    import urllib.error
    import urllib.request

    from opfor.scenarios.attacksurface import config
    from opfor.scenarios.attacksurface.sources import domains

    monkeypatch.setattr(config, "certspotter_token", lambda: "tok")

    # a non-429 stays loud, it is not a quota signal and must not be swallowed as empty
    def fake_urlopen(request, timeout=0):
        raise urllib.error.HTTPError(request.full_url, 500, "Server Error", {}, None)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(urllib.error.HTTPError):
        domains.certspotter_subdomains("example.com")


def test_pivot_failure_still_closes_and_is_loud():
    def boom(domain):
        raise TimeoutError("certspotter slow")

    scenario = _make(pivot_fn=boom)
    world = _seed()
    report = run(scenario, world, scope=Scope(max_tier="recon", hosts=(ROOT,)), budget=Budget(500))
    assert report.closed
    assert any("failed" in n and "domain_pivot" in n for n in report.notes)


def _with_reverse(reverse_fn=_reverse):
    return _make(reverse_whois_fn=reverse_fn)


def test_registrant_pivot_is_off_without_a_key():
    # the default seam stays off when no key is set, so the run has no registrant fact
    world = _seed()
    _run(world)
    assert not world.has_fact("org:ExampleCorp", "registrant")


def test_registrant_pivot_discovers_a_root_when_wired():
    world = _seed()
    run(_with_reverse(), world, scope=Scope(max_tier="recon", hosts=(ROOT,)), budget=Budget(500))
    org = world.node("domain:example.org")
    assert org is not None
    assert org.payload.source == "reverse-whois"
    assert org.payload.confidence == "confirmed"
    assert "registration record names ExampleCorp" in org.payload.evidence


def test_registrant_root_is_an_info_finding():
    world = _seed()
    report = run(_with_reverse(), world, scope=Scope(max_tier="recon", hosts=(ROOT,)), budget=Budget(500))
    roots = {f.where: f for f in report.findings if f.data.get("kind") == "root"}
    assert "example.org" in roots
    assert roots["example.org"].data["source"] == "reverse-whois"


def test_registrant_pivot_failure_still_closes_and_is_loud():
    def boom(term, api_key=""):
        raise TimeoutError("provider slow")

    world = _seed()
    report = run(_with_reverse(boom), world, scope=Scope(max_tier="recon", hosts=(ROOT,)), budget=Budget(500))
    assert report.closed
    assert any("failed" in n and "domain_registrant" in n for n in report.notes)


def test_roots_from_reverse_whois_reads_both_shapes():
    from opfor.scenarios.attacksurface.sources.domains import roots_from_reverse_whois

    as_strings = {"domainsList": ["a.example.org", "b.example.net"]}
    assert roots_from_reverse_whois(as_strings, "Acme") == {
        "example.org": "registration record names Acme",
        "example.net": "registration record names Acme",
    }
    as_records = {"domainsList": [{"domainName": "c.example.io"}]}
    assert roots_from_reverse_whois(as_records, "Acme") == {
        "example.io": "registration record names Acme"
    }


# --- interface enrichment sources ------------------------------------------------------


def test_openapi_spec_is_expanded_into_its_operations():
    world = _seed()
    _run(world)
    specs = [f.payload for f in world.facts("api_spec")]
    hit = [s for s in specs if s.base == "https://spa.example.com/openapi.json"]
    assert hit and hit[0].count == 2
    assert "GET /users" in hit[0].paths


def test_graphql_introspection_fact_reads_query_and_mutation():
    world = _seed()
    _run(world)
    schemas = [f.payload for f in world.facts("graphql")]
    hit = [s for s in schemas if s.enabled and s.count == 3]
    assert hit and "query:me" in hit[0].operations


def test_spec_fetch_failure_still_closes_and_is_loud():
    def boom(name, path):
        raise TimeoutError("spec slow")

    scenario = _make(fetch_doc_fn=boom)
    world = _seed()
    report = run(scenario, world, scope=Scope(max_tier="recon", hosts=(ROOT,)), budget=Budget(2000))
    assert report.closed
    assert any("failed" in n and "endpoint_expand_spec" in n for n in report.notes)


def test_paths_from_openapi_names_methods():
    from opfor.scenarios.attacksurface.sources.domains import paths_from_openapi

    doc = {"paths": {"/a": {"get": {}, "post": {}}, "/b": {"get": {}}}}
    assert set(paths_from_openapi(doc)) == {"GET,POST /a", "GET /b"}
    assert paths_from_openapi({}) == []
    assert paths_from_openapi({"paths": "not a map"}) == []


def test_operations_from_introspection_reads_query_and_mutation():
    from opfor.scenarios.attacksurface.sources.domains import operations_from_introspection

    data = {"__schema": {"queryType": {"fields": [{"name": "me"}]},
                         "mutationType": {"fields": [{"name": "login"}]}}}
    assert operations_from_introspection(data) == ["mutation:login", "query:me"]
    assert operations_from_introspection({}) == []


def test_subdomains_from_vt_reads_relationship_ids():
    from opfor.scenarios.attacksurface.sources.domains import subdomains_from_vt

    page = {"data": [{"id": "api.example.com"}, {"id": "*.mail.example.com"},
                     {"id": "unrelated.test"}]}
    # a wildcard keeps its star, so the enumeration can flag it rather than lose it
    assert subdomains_from_vt(page, "example.com") == {"api.example.com", "*.mail.example.com"}


def test_virustotal_is_skipped_without_a_key(monkeypatch):
    from opfor.scenarios.attacksurface.sources import domains as d

    monkeypatch.delenv("OPFOR_VIRUSTOTAL_KEY", raising=False)
    # no key means the source contributes nothing and makes no network call
    assert d.virustotal_subdomains("example.com") == set()


def test_javascript_endpoint_extraction_finds_a_hidden_api():
    # /api/secret is only named inside a script bundle, never linked, so finding it proves
    # the endpoint discovery reads the app's own JavaScript
    world = _seed()
    _run(world)
    assert world.node("endpoint:admin.example.com/api/secret") is not None


def test_cross_host_javascript_path_is_probed_on_the_sibling_host():
    # /v2/balance is named only by a full url inside admin.example.com's script, and it
    # points at api.example.com, so finding it there proves cross-host harvest
    world = _seed()
    _run(world)
    assert world.node("endpoint:api.example.com/v2/balance") is not None


def test_wayback_passive_urls_become_candidates():
    world = _seed()
    _run(world)
    assert world.node("endpoint:www.example.com/legacy") is not None


def test_robots_disallow_paths_become_candidates():
    world = _seed()
    _run(world)
    assert world.node("endpoint:example.com/secret-panel") is not None


def test_javascript_and_url_parsing():
    from opfor.scenarios.attacksurface.sources.domains import (
        paths_in_javascript,
        same_host_path,
        script_sources,
        urls_in_javascript,
    )

    js = 'fetch("/api/v1/users");const a="/static/x.js";x("//cdn/y");u("https://api.h/z")'
    got = paths_in_javascript(js)
    assert "/api/v1/users" in got and "/static/x.js" in got
    assert not any(p.startswith("//") for p in got)
    assert urls_in_javascript(js) == ["https://api.h/z"]
    assert script_sources('<script src="/a.js"></script><script src="https://cdn/b.js">', "h.test") == ["/a.js"]
    assert same_host_path("/p?q=1", "h.test") == "/p"
    assert same_host_path("https://h.test/x", "h.test") == "/x"
    assert same_host_path("https://other/x", "h.test") is None


def test_robots_and_sitemap_parsing():
    from opfor.scenarios.attacksurface.sources.domains import robots_entries, sitemap_paths

    paths, sitemaps = robots_entries("User-agent: *\nDisallow: /admin\nAllow: /public\nSitemap: https://h/sm.xml")
    assert paths == ["/admin", "/public"]
    assert sitemaps == ["https://h/sm.xml"]
    assert sitemap_paths("<urlset><url><loc>https://h.test/a</loc></url></urlset>", "h.test") == ["/a"]

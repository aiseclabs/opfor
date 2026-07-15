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
    # an inventory host supplied from a DNS export, hidden behind the *.dev wildcard
    "api.dev.example.com": {"resolvable": True, "addresses": ("1.1.1.9",)},
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
GH_ORGS = {"ExampleCorp": [
    # its profile links to the in-scope root, so it is attributed to the target
    {"login": "examplecorp", "url": "https://github.com/examplecorp", "org_id": 7,
     "name": "Example Corp", "blog": "https://example.com", "email": "", "verified": False},
]}
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


def _identify(evidence):
    # By default nothing is identified, so the cve scan is a quiet no-op and never touches
    # the triage MockProvider. A test that drives a product overrides this seam.
    return {"product": "", "version": "", "cpe": ""}


def _cves(product, version, cpe=""):
    return []


def _probe_url(url):
    # By default every derived bucket name is absent, so the bucket scan is a quiet no-op. A
    # test that drives a listable bucket overrides this seam.
    return {"status": 404, "url": url, "content_type": "", "body": ""}


def _make(**over):
    """Build the scenario with every seam faked, so no test touches the network or the
    model. A MockProvider stands in for the triage model, returning an empty result by
    default. A test overrides one seam to drive a failure or a variant, or passes its own
    provider to drive a canned model reply."""
    seams = dict(search_fn=_search, repos_fn=_repos, enumerate_fn=_enumerate, pivot_fn=_pivot,
                 resolve_fn=_resolve, probe_fn=_probe, fetch_fn=_fetch, fetch_doc_fn=_fetch_doc,
                 introspect_fn=_introspect, wayback_fn=_wayback, identify_fn=_identify, cve_fn=_cves,
                 probe_url_fn=_probe_url)
    seams.update(over)
    seams.setdefault("provider", MockProvider(default='{"findings": []}'))
    seams.setdefault("model", "test-model")
    return build(**seams)


def _scenario():
    return _make()


def _seed(*, domains=(ROOT,), hosts=(), classes=()):
    world = World()
    world.add(Node(id="org:ExampleCorp", type="org",
                   payload=Org(name="ExampleCorp", domains=tuple(domains), hosts=tuple(hosts),
                               classes=tuple(classes))))
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


def test_truncated_enumeration_is_reported_as_a_blind_spot():
    # a passive source that stopped at its page cap left subdomains unfetched, the run must
    # say so rather than present the bounded set as the complete surface
    from opfor.scenarios.attacksurface.classes.domain.sources import Enumeration

    def enum_truncated(root):
        found = Enumeration({"api.example.com"})
        found.truncated = True
        return found

    report, _scenario, _world = _run_capturing(enumerate_fn=enum_truncated)
    trunc = [f for f in report.findings if f.id == "finding:blindspot:enumeration"]
    assert len(trunc) == 1
    assert trunc[0].severity == "INFO"
    assert "example.com" in trunc[0].data["roots"]


def test_hosts_from_file_normalizes_a_dns_export(tmp_path):
    from opfor.scenarios.attacksurface.classes.domain.sources import hosts_from_file

    export = tmp_path / "dns.txt"
    export.write_text(
        "# a dns export\n"
        "\n"
        "api.dev.example.com\n"
        "*.sandbox.example.com\n"                                  # wildcard base is a real host
        "_0007c31f57915f7fdc0b0f3de4b50248.api.hodor.example.com\n"  # ACM record wraps a host
        "sel._domainkey.example.com\n"                            # DKIM control record, dropped
        "API.DEV.EXAMPLE.COM\n",                                  # duplicate after lowercasing
        encoding="utf-8")
    hosts = hosts_from_file(str(export))
    assert hosts == ("api.dev.example.com", "api.hodor.example.com", "sandbox.example.com")


def test_inventory_hosts_enter_the_surface_as_enriched_leaves():
    # a DNS-export host is resolved and triaged, but not re-enumerated, since it is a leaf
    world = _seed(hosts=("api.dev.example.com",))
    _run(world)
    node = world.node("domain:api.dev.example.com")
    assert node.payload.source == "inventory"
    assert node.payload.root == "example.com"
    assert world.has_fact(node.id, "resolved")
    assert not world.has_fact(node.id, "enumerated")


def test_wildcard_base_node_is_flagged():
    from opfor.core import Node, World
    from opfor.scenarios.attacksurface.classes.domain.capabilities import Subdomains
    from opfor.scenarios.attacksurface.classes.domain.types import DomainData
    from opfor.scenarios.attacksurface.types import Org

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

    from opfor.scenarios.attacksurface.classes.domain import sources as domains

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


def test_http_probe_tries_every_public_ip_retries_timeouts_and_raises_the_unexpected(monkeypatch):
    from opfor.scenarios.attacksurface.classes.domain import sources as domains

    # the first public address refuses on both schemes, the second answers, so a multi-ip
    # name is alive rather than judged dead on the first unlucky address
    calls = []

    def refuse_first_ip(name, ip, scheme, path, **kw):
        calls.append((ip, scheme))
        if ip == "8.8.8.8":
            raise ConnectionRefusedError()
        return (200, "nginx", "text/html", "<title>ok</title>", "", ())

    monkeypatch.setattr(domains, "_connect", refuse_first_ip)
    result = domains.http_probe("host.example.com", ("8.8.8.8", "1.1.1.1"))
    assert result["alive"] is True
    assert result["status"] == 200
    assert ("1.1.1.1", "https") in calls

    # a timeout is transient, so it is retried and the live server on the retry is found
    state = {"n": 0}

    def timeout_then_ok(name, ip, scheme, path, **kw):
        state["n"] += 1
        if state["n"] == 1:
            raise TimeoutError()
        return (200, "nginx", "text/html", "", "", ())

    monkeypatch.setattr(domains, "_connect", timeout_then_ok)
    assert domains.http_probe("host.example.com", ("8.8.8.8",))["alive"] is True
    assert state["n"] >= 2

    # an unexpected error is raised loud, never passed off as not alive
    def raise_bug(name, ip, scheme, path, **kw):
        raise ValueError("bug")

    monkeypatch.setattr(domains, "_connect", raise_bug)
    with pytest.raises(ValueError):
        domains.http_probe("host.example.com", ("8.8.8.8",))

    # a private-only host has no public address, reported not alive without a connection
    assert domains.http_probe("host.example.com", ("10.0.0.1",))["alive"] is False

    # the redirect target is captured, so a host fronted by an identity proxy is visible to
    # triage rather than read as a plain live host
    def connect_redirect(name, ip, scheme, path, **kw):
        return (302, "", "text/html", "", "https://accounts.google.com/o/oauth2/v2/auth",
                (("www-authenticate", "Bearer"),))

    monkeypatch.setattr(domains, "_connect", connect_redirect)
    redirected = domains.http_probe("host.example.com", ("8.8.8.8",))
    assert redirected["alive"] is True
    assert redirected["location"] == "https://accounts.google.com/o/oauth2/v2/auth"
    assert redirected["headers"] == (("www-authenticate", "Bearer"),)


def test_signal_headers_keeps_identity_drops_noise_and_masks_cookie_value():
    from opfor.scenarios.attacksurface.classes.domain import sources as domains

    class _Resp:
        def getheaders(self):
            return [("Server", "nginx"), ("Date", "Mon"), ("Content-Length", "10"),
                    ("X-Powered-By", "Express"), ("WWW-Authenticate", "Bearer realm=x"),
                    ("Set-Cookie", "_gitlab_session=secretvalue; Path=/")]

    hdrs = dict(domains._signal_headers(_Resp()))
    # identity headers are kept, noise is dropped
    assert hdrs["x-powered-by"] == "Express"
    assert hdrs["www-authenticate"] == "Bearer realm=x"
    assert hdrs["server"] == "nginx"
    assert "date" not in hdrs and "content-length" not in hdrs
    # a cookie is reduced to its name, the value is a secret and is dropped
    assert hdrs["set-cookie"] == "_gitlab_session"


def test_nvd_cves_parses_id_score_severity_and_summary():
    from opfor.scenarios.attacksurface.classes.domain import sources as domains

    reply = {
        "vulnerabilities": [
            {"cve": {
                "id": "CVE-2021-39226",
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
                            "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}]},
                "descriptions": [{"lang": "es", "value": "ignore"}, {"lang": "en", "value": "auth bypass"}],
                "references": [{"url": "https://advisory.example/GHSA-1"}, {"url": "https://nvd.example/CVE-2021-39226"}],
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


def test_nvd_cves_returns_nothing_for_an_unidentified_product():
    from opfor.scenarios.attacksurface.classes.domain import sources as domains

    # no product means nothing to query, an empty list without a network call
    assert domains.nvd_cves("", "1.0") == []


def test_nvd_keyword_search_uses_the_product_alone_not_the_version(monkeypatch):
    """NVD keyword search matches the description text, where a version rarely appears, so
    the query is the product alone, or a version-bearing product would return nothing."""
    from opfor.scenarios.attacksurface.classes.domain import sources as domains

    queries = []
    monkeypatch.setattr(domains, "_nvd_fetch", lambda q: queries.append(q) or [])
    domains.nvd_cves("litellm", "1.90.0")
    assert queries == ["keywordSearch=litellm"]


def test_nvd_falls_back_to_a_product_keyword_when_the_cpe_match_is_empty(monkeypatch):
    """A wrong vendor guess or a cve not tagged with the cpe yields an empty cpe match, so
    the query falls back to a product keyword rather than missing a real advisory."""
    from opfor.scenarios.attacksurface.classes.domain import sources as domains

    queries = []

    def fake_fetch(query):
        queries.append(query)
        if query.startswith("virtualMatchString"):
            return []
        return [{"id": "CVE-2026-40217"}]

    monkeypatch.setattr(domains, "_nvd_fetch", fake_fetch)
    result = domains.nvd_cves("litellm", "1.90.0", cpe="berriai:litellm")
    assert result == [{"id": "CVE-2026-40217"}]
    assert len(queries) == 2
    assert queries[0].startswith("virtualMatchString")
    assert queries[1] == "keywordSearch=litellm"


def test_nvd_cpe_match_with_results_does_not_fall_back(monkeypatch):
    from opfor.scenarios.attacksurface.classes.domain import sources as domains

    queries = []
    monkeypatch.setattr(domains, "_nvd_fetch",
                        lambda q: queries.append(q) or [{"id": "CVE-2020-0001"}])
    result = domains.nvd_cves("grafana", "9.0.0", cpe="grafana:grafana")
    assert result == [{"id": "CVE-2020-0001"}]
    assert len(queries) == 1
    assert queries[0].startswith("virtualMatchString")


def test_nvd_throttle_serializes_calls_to_stay_under_the_rate_limit(monkeypatch):
    from opfor.scenarios.attacksurface.classes.domain import sources as domains

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
    scans = [f.payload for f in world.facts("cve_scanned") if f.payload.product]
    assert scans, "expected a cve_scanned fact carrying a product"
    assert scans[0].product == "grafana" and scans[0].version == "8.0.0"
    assert any(c.id == "CVE-2021-39226" and c.severity == "CRITICAL" for c in scans[0].cves)


def test_source_map_parser_detects_inlined_source_and_paths_only():
    from opfor.scenarios.attacksurface.classes.domain import sources as domains

    inlined = json.dumps({"version": 3, "sources": ["../src/app.ts", "../src/api.ts"],
                          "sourcesContent": ["export const x = 1", ""]})
    r = domains.source_map_from_text(inlined)
    assert r["has_sources_content"] is True
    assert r["sources_count"] == 2
    assert "../src/app.ts" in r["sample_sources"]

    # a map that lists paths but inlines no content is a lesser leak, not None
    paths_only = json.dumps({"version": 3, "sources": ["../src/app.ts"], "sourcesContent": [None]})
    assert domains.source_map_from_text(paths_only)["has_sources_content"] is False

    # ordinary json and an empty body are not source maps
    assert domains.source_map_from_text('{"hello": "world"}') is None
    assert domains.source_map_from_text("") is None


def test_source_map_scan_flags_an_inlined_map():
    home = '<script src="/assets/app.abc.js"></script>'
    mapdoc = json.dumps({"version": 3, "sources": ["../src/secret.ts"],
                         "sourcesContent": ["const API_KEY = 'x'"]})

    def fetch_doc(name, path):
        if path == "/":
            return {"text": home}
        if path.endswith(".map"):
            return {"text": mapdoc}
        return {"text": ""}

    report, _scenario, world = _run_capturing(fetch_doc_fn=fetch_doc)
    leaks = [f.payload for f in world.facts("source_maps") if f.payload.leaks]
    assert leaks, "expected a source_maps fact carrying a leak"
    leak = leaks[0].leaks[0]
    assert leak.has_sources_content is True
    assert leak.url.endswith("/assets/app.abc.js.map")


def test_secrets_in_text_matches_patterns_and_redacts():
    from opfor.scenarios.attacksurface.classes.domain import sources as domains

    patterns = [
        {"id": "aws-access-key-id", "regex": "AKIA[0-9A-Z]{16}", "note": "an AWS access key id"},
        {"id": "never", "regex": "ZZZZ[0-9]{40}", "note": "no match"},
    ]
    body = "const k = 'AKIAIOSFODNN7EXAMPLE'; const ok = 1;"
    hits = domains.secrets_in_text(body, patterns)
    assert len(hits) == 1
    assert hits[0]["pattern"] == "aws-access-key-id"
    # the sample is redacted, a prefix and a length, never the full key
    assert "AKIAIOSFODNN7EXAMPLE" not in hits[0]["sample"]
    assert hits[0]["sample"].startswith("AKIAIO")


def test_secret_scan_flags_a_key_in_a_bundle_and_redacts_it():
    home = '<script src="/static/main.js"></script>'
    bundle = "var cfg={awsKey:'AKIAIOSFODNN7EXAMPLE'};"
    patterns = [{"id": "aws-access-key-id", "regex": "AKIA[0-9A-Z]{16}", "note": "an AWS access key id"}]

    def fetch_doc(name, path):
        if path == "/":
            return {"text": home}
        if path == "/static/main.js":
            return {"text": bundle}
        return {"text": ""}

    report, _scenario, world = _run_capturing(fetch_doc_fn=fetch_doc)
    # the planner hands the real patterns from secret_patterns.yaml, which includes the aws
    # key shape, so the scan matches without the test injecting patterns
    hits = [f.payload for f in world.facts("secrets_in_js") if f.payload.matches]
    assert hits, "expected a secrets_in_js fact carrying a match"
    match = hits[0].matches[0]
    assert match.pattern == "aws-access-key-id"
    assert "AKIAIOSFODNN7EXAMPLE" not in match.sample


def test_backup_candidates_derives_twins_and_skips_directories():
    from opfor.scenarios.attacksurface.classes.domain import sources as domains

    twins = domains.backup_candidates(
        "/app/config.php", append=(".bak", "~"), rename=(".zip",), swap=(".{file}.swp",))
    assert "/app/config.php.bak" in twins
    assert "/app/config.php~" in twins
    assert "/app/config.zip" in twins           # the extension is replaced, an archive twin
    assert "/app/.config.php.swp" in twins      # the vim swap dotfile over the filename
    # a directory or a bare root has no filename to derive from
    assert domains.backup_candidates("/app/", append=(".bak",)) == []
    assert domains.backup_candidates("/", append=(".bak",)) == []
    # a file with no extension takes an append twin but no extension-rename twin
    assert domains.backup_candidates("/README", append=("~",), rename=(".zip",)) == ["/README~"]


def test_backup_scan_finds_a_twin_of_an_observed_file():
    home = '<html><body><a href="/config.php">cfg</a></body></html>'
    source = "<?php $db_pass='s3cr3t'; ?>"

    def fetch(name, addresses, path):
        url = f"https://{name}{path}"
        miss = {"status": 404, "url": url, "content_type": "", "server": "", "title": "", "body": ""}
        if name != "admin.example.com":
            return miss
        if path == "/config.php":
            return {"status": 200, "url": url, "content_type": "text/html",
                    "server": "nginx", "title": "", "body": "rendered page"}
        if path == "/config.php.bak":
            return {"status": 200, "url": url, "content_type": "text/plain",
                    "server": "nginx", "title": "", "body": source}
        return miss

    def fetch_doc(name, path):
        if name == "admin.example.com" and path == "/":
            return {"status": 200, "content_type": "text/html", "text": home}
        return {"status": None, "content_type": "", "text": ""}

    report, _scenario, world = _run_capturing(fetch_fn=fetch, fetch_doc_fn=fetch_doc)
    hits = [h for f in world.facts("backups") for h in f.payload.hits]
    assert any(h.url.endswith("/config.php.bak") and h.size > 0 for h in hits), \
        "expected a backups fact carrying the config.php.bak twin"


def test_cloud_bucket_from_url_recognizes_provider_forms():
    from opfor.scenarios.attacksurface.classes.domain import sources as domains

    s3v = domains.cloud_bucket_from_url("https://my-bucket.s3.amazonaws.com/key.txt")
    assert s3v["provider"] == "s3" and s3v["bucket"] == "my-bucket"
    s3r = domains.cloud_bucket_from_url("https://s3.eu-west-1.amazonaws.com/other-bucket/x")
    assert s3r["provider"] == "s3" and s3r["bucket"] == "other-bucket"
    gcs = domains.cloud_bucket_from_url("https://storage.googleapis.com/data-bucket/o")
    assert gcs["provider"] == "gcs" and gcs["bucket"] == "data-bucket"
    # a bare host, the shape a CNAME takes, is recognized without a scheme
    cname = domains.cloud_bucket_from_url("assets-bucket.s3.us-east-2.amazonaws.com")
    assert cname["provider"] == "s3" and cname["bucket"] == "assets-bucket"
    az = domains.cloud_bucket_from_url("https://acct.blob.core.windows.net/container/blob")
    assert az["provider"] == "azure" and az["bucket"] == "acct/container"
    # an azure account with no container cannot be listed, so it is not a bucket here
    assert domains.cloud_bucket_from_url("acct.blob.core.windows.net") is None
    # a non-cloud url is not a bucket
    assert domains.cloud_bucket_from_url("https://example.com/path") is None
    # the reference extractor keeps only cloud-storage hosts
    refs = domains.cloud_refs_in_text('a="https://x.s3.amazonaws.com/k"; b="https://example.com/y"')
    assert refs == ["https://x.s3.amazonaws.com/k"]
    # a public object listing is told apart from a generic 200 page
    assert domains.bucket_listable("<ListBucketResult><Contents>x</Contents></ListBucketResult>")
    assert not domains.bucket_listable("<html>welcome</html>")


def test_bucket_scan_checks_buckets_the_target_reveals_by_cname():
    listing = "<ListBucketResult><Contents><Key>dump.sql</Key></Contents></ListBucketResult>"

    def resolve(name):
        base = _resolve(name)
        if name == "admin.example.com":
            return {**base, "cnames": ("example-backup.s3.amazonaws.com",)}
        if name == "www.example.com":
            return {**base, "cnames": ("example-private.s3.amazonaws.com",)}
        return base

    def probe_url(url):
        if "example-backup.s3" in url:
            return {"status": 200, "url": url, "content_type": "application/xml", "body": listing}
        if "example-private.s3" in url:
            return {"status": 403, "url": url, "content_type": "application/xml", "body": ""}
        return {"status": 404, "url": url, "content_type": "", "body": ""}

    report, _scenario, world = _run_capturing(resolve_fn=resolve, probe_url_fn=probe_url)
    buckets = [b for f in world.facts("buckets") for b in f.payload.buckets]
    listable = [b for b in buckets if b.state == "listable"]
    assert any(b.name == "example-backup" and b.provider == "s3"
               and b.evidence == "CNAME from admin.example.com" for b in listable), \
        "expected the listable example-backup S3 bucket discovered by CNAME"
    assert any(b.name == "example-private" and b.state == "private" for b in buckets), \
        "expected the private example-private bucket"


def test_endpoint_probe_records_a_coverage_gap_when_a_path_errors():
    # one candidate path errors on the probe. The scan still returns the endpoints it
    # reached, but the dropped path is recorded as a coverage gap and surfaced as an INFO
    # finding, so a partial probe is never read as a clean, complete negative, invariant 5.
    def fetch(name, addresses, path):
        if name == "admin.example.com" and path == "/.git/config":
            raise TimeoutError("probe timed out")
        return _fetch(name, addresses, path)

    report, _scenario, world = _run_capturing(fetch_fn=fetch)
    gaps = [f.payload for f in world.facts("coverage_gap") if f.payload.scan == "domain_endpoints"]
    assert any(g.host == "admin.example.com" and g.failed >= 1 for g in gaps), \
        "a probe error must record a coverage_gap fact rather than be silently dropped"
    gap_findings = [f for f in report.findings if f.data.get("kind") == "coverage_gap"]
    assert any(f.severity == "INFO" and "admin.example.com" in f.where for f in gap_findings), \
        "the coverage gap must surface as an INFO finding, so a partial scan reads as partial"
    assert "TimeoutError" in "".join(f.evidence for f in gap_findings)


def test_backup_scan_records_a_coverage_gap_when_a_twin_errors():
    home = '<html><body><a href="/config.php">cfg</a></body></html>'

    def fetch(name, addresses, path):
        url = f"https://{name}{path}"
        miss = {"status": 404, "url": url, "content_type": "", "server": "", "title": "", "body": ""}
        if name != "admin.example.com":
            return miss
        if path == "/config.php":
            return {"status": 200, "url": url, "content_type": "text/html",
                    "server": "nginx", "title": "", "body": "rendered page"}
        if path == "/config.php.bak":
            raise ConnectionResetError("reset during backup twin probe")
        return miss

    def fetch_doc(name, path):
        if name == "admin.example.com" and path == "/":
            return {"status": 200, "content_type": "text/html", "text": home}
        return {"status": None, "content_type": "", "text": ""}

    _report, _scenario, world = _run_capturing(fetch_fn=fetch, fetch_doc_fn=fetch_doc)
    gaps = [f.payload for f in world.facts("coverage_gap") if f.payload.scan == "backup_scan"]
    assert any(g.failed >= 1 and any("ConnectionResetError" in r for r in g.reasons) for g in gaps), \
        "a backup twin probe error must record a coverage_gap rather than vanish"


def test_bucket_scan_records_a_coverage_gap_when_a_probe_errors():
    listing = "<ListBucketResult><Contents><Key>dump.sql</Key></Contents></ListBucketResult>"

    def resolve(name):
        base = _resolve(name)
        if name == "admin.example.com":
            return {**base, "cnames": ("example-backup.s3.amazonaws.com",)}
        if name == "www.example.com":
            return {**base, "cnames": ("example-private.s3.amazonaws.com",)}
        return base

    def probe_url(url):
        if "example-backup.s3" in url:
            return {"status": 200, "url": url, "content_type": "application/xml", "body": listing}
        if "example-private.s3" in url:
            raise TimeoutError("bucket probe timed out")
        return {"status": 404, "url": url, "content_type": "", "body": ""}

    report, _scenario, world = _run_capturing(resolve_fn=resolve, probe_url_fn=probe_url)
    # the reachable bucket is still reported, the errored one is a coverage gap, not a silent drop
    buckets = [b for f in world.facts("buckets") for b in f.payload.buckets]
    assert any(b.name == "example-backup" for b in buckets)
    gaps = [f.payload for f in world.facts("coverage_gap") if f.payload.scan == "bucket_scan"]
    assert any(g.failed >= 1 for g in gaps), \
        "an errored bucket probe must record a coverage_gap rather than be silently skipped"
    assert any(f.data.get("kind") == "coverage_gap" and f.data.get("scan") == "bucket_scan"
               for f in report.findings)


def test_cve_scan_fails_loud_when_identification_errors():
    # a model or lookup error is a loud Failed, never a silent empty result, invariant 5
    def boom(evidence):
        raise RuntimeError("model down")

    report, _scenario, _world = _run_capturing(identify_fn=boom)
    assert any("cve_scan" in note and "model down" in note for note in report.notes)


def test_probe_list_includes_product_identity_and_version_paths():
    from opfor.scenarios.attacksurface.classes.domain import planner

    # the product identity and version endpoints are data in paths.yaml, probed by the
    # existing endpoint capability, so a later step can read the version for a cve match
    for path in ("/actuator/info", "/version", "/.well-known/openid-configuration", "/nacos/"):
        assert path in planner._PROBE_PATHS


def test_batch_one_exposure_coverage_is_loaded():
    from opfor.scenarios.attacksurface.classes import domain as domain_class
    from opfor.scenarios.attacksurface.classes.domain import planner
    from opfor.scenarios.attacksurface.triage import _load_classes, _load_clues

    # new fixed-path leaks are probed, pure data in paths.yaml, no code
    for path in ("/.ssh/id_rsa", "/web.config", "/backup.sql", "/.git/index", "/.npmrc"):
        assert path in planner._PROBE_PATHS

    knowledge = domain_class.KNOWLEDGE
    # new deterministic clues direct the model at the buried signals
    clue_ids = {c["id"] for c in _load_clues(knowledge / "exposures.yaml")}
    assert {"exposed-private-key", "exposed-htpasswd", "exposed-sql-dump"} <= clue_ids
    # new judgment families the model can reach for
    class_ids = {c["id"] for c in _load_classes(knowledge / "classes")}
    assert {"cors-misconfiguration", "verbose-error-disclosure"} <= class_ids


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
    from opfor.scenarios.attacksurface.classes.domain.types import Endpoint

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


def test_github_attribution_keeps_the_owned_drops_the_namesake_flags_the_unproven():
    # three candidates match the name: one links to the in-scope root, one links to a
    # different root and is a namesake, one has no link and cannot be proven either way
    def search(name, token=""):
        return [
            {"login": "examplecorp", "url": "u", "org_id": 1, "name": "Example Corp",
             "blog": "https://example.com", "email": "", "verified": False},
            {"login": "example-lasers", "url": "u", "org_id": 2, "name": "Example Lasers",
             "blog": "https://example-lasers.io", "email": "", "verified": False},
            {"login": "examplish", "url": "u", "org_id": 3, "name": "Examplish",
             "blog": "", "email": "", "verified": False},
        ]

    report, _, world = _run_capturing(_seed(), search_fn=search)
    logins = {n.payload.login for n in world.nodes("github_org")}
    # the namesake proven to belong elsewhere is dropped, the other two are kept
    assert logins == {"examplecorp", "examplish"}
    attributed = {n.payload.login for n in world.nodes("github_org") if n.payload.attributed}
    assert attributed == {"examplecorp"}
    # the owned org is its own finding, the unproven one is collapsed into a caveat
    kinds = {f.data.get("kind") for f in report.findings}
    assert "github_org" in kinds and "github_unattributed" in kinds
    caveat = next(f for f in report.findings if f.data.get("kind") == "github_unattributed")
    assert caveat.data["logins"] == ["examplish"]


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
    assert git[0].poc.startswith("curl")
    assert git[0].data["confidence"] == 0.9


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


def test_grounding_attaches_a_poc_request_only_for_an_observed_safe_read():
    """Strict grounding: a finding is marked reproducible only when its safe-read proof of
    concept names a GET the surface actually recorded, never a request the model invented."""
    from opfor.core import Fact, Node
    from opfor.scenarios.attacksurface.classes.domain.types import (
        DomainData, Endpoint, SpecAudit, SpecOperation)
    from opfor.core.result import Finding
    from opfor.scenarios.attacksurface.grounding import FindingGrounder

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
    from opfor.scenarios.attacksurface.classes.domain.types import DomainData, Endpoint, Resolved
    from opfor.scenarios.attacksurface.grounding import FindingGrounder
    from opfor.scenarios.attacksurface.triage import SurfaceTriage

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


# --- the confirm regrade against the live receipt --------------------------------------


def _claim(fid, *, severity="MEDIUM", where="https://h/x", title="t"):
    from opfor.core import Finding
    return Finding(id=fid, title=title, severity=severity, where=where,
                   evidence="judged from the report", poc=f"safe read: curl -s {where}")


def _receipt(**over):
    from opfor.scenarios.attacksurface.reproduce import Reproduction
    fields = dict(method="GET", url="https://h/x", status=200,
                  content_type="application/json", size=12, excerpt='{"ok": true}', error="")
    fields.update(over)
    return Reproduction(**fields)


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
    from opfor.scenarios.attacksurface.net import registrable_root

    assert registrable_root("api.example.com") == "example.com"
    assert registrable_root("example.com") == "example.com"
    assert registrable_root("a.b.example.co.uk") == "example.co.uk"


def test_shared_certificate_is_not_treated_as_ownership_evidence():
    from opfor.scenarios.attacksurface.classes.domain.sources import sibling_roots_from_issuances

    # a dedicated cert bundling two roots yields the sibling
    dedicated = [{"dns_names": ["example.com", "www.example.net"]}]
    assert sibling_roots_from_issuances(dedicated, "example.com") == {
        "example.net": "shares a certificate with example.com, 2 roots on the cert"
    }
    # a multi-tenant cert bundling many unrelated roots proves nothing, so it is skipped
    shared = [{"dns_names": ["example.com", "a.org", "b.org", "c.org", "d.org", "e.org", "f.org"]}]
    assert sibling_roots_from_issuances(shared, "example.com") == {}


def test_cert_sibling_pivot_walks_past_the_first_page(monkeypatch):
    import urllib.request

    from opfor.scenarios.attacksurface import config
    from opfor.scenarios.attacksurface.classes.domain import sources as domains

    monkeypatch.setattr(config, "certspotter_token", lambda: None)

    class _Resp:
        def __init__(self, payload):
            self._payload = payload

        def read(self):
            return json.dumps(self._payload).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    # page one holds only the seed's own cert, the sibling rides a cert reached only once
    # the walk follows the `after` cursor to the next page, so a single-page fetch misses it
    pages = {
        "": [{"id": "1", "dns_names": ["example.com"]}],
        "1": [{"id": "2", "dns_names": ["example.com", "example.net"]}],
    }

    def fake_urlopen(request, timeout=0):
        after = request.full_url.split("after=")[1] if "after=" in request.full_url else ""
        return _Resp(pages.get(after, []))

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    assert domains.cert_sibling_roots("example.com") == {
        "example.net": "shares a certificate with example.com, 2 roots on the cert"
    }


def test_virustotal_enumeration_flags_truncation_at_the_page_cap(monkeypatch):
    import urllib.request

    from opfor.scenarios.attacksurface import config
    from opfor.scenarios.attacksurface.classes.domain import sources as domains

    monkeypatch.setattr(config, "virustotal_key", lambda: "vt")

    class _Resp:
        def __init__(self, payload):
            self._payload = payload

        def read(self):
            return json.dumps(self._payload).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    # every page answers with a record and a next cursor, so the walk never exhausts the
    # cursor and stops only at the page cap, which means more subdomains remain unfetched
    _next = "https://www.virustotal.com/api/v3/domains/example.com/subdomains?cursor=more"

    def capped(request, timeout=0):
        return _Resp({"data": [{"id": "api.example.com"}], "links": {"next": _next}})

    monkeypatch.setattr(urllib.request, "urlopen", capped)
    result = domains.virustotal_subdomains("example.com")
    assert result.truncated is True
    assert "api.example.com" in result

    # a walk that exhausts the cursor before the cap is complete, not truncated
    def exhausts(request, timeout=0):
        return _Resp({"data": [{"id": "api.example.com"}], "links": {}})

    monkeypatch.setattr(urllib.request, "urlopen", exhausts)
    assert domains.virustotal_subdomains("example.com").truncated is False


def test_otx_passive_dns_parses_and_flags_the_cap(monkeypatch):
    import urllib.request

    from opfor.scenarios.attacksurface import config
    from opfor.scenarios.attacksurface.classes.domain import sources as domains

    # the parse keeps hosts under the domain and drops the apex and any other domain, apart
    # from the network so it is driven by a fixture
    reply = {"passive_dns": [
        {"hostname": "api.example.com"},
        {"hostname": "dev.example.com."},
        {"hostname": "example.com"},
        {"hostname": "other.test"},
    ]}
    assert domains.subdomains_from_otx(reply, "example.com") == {"api.example.com", "dev.example.com"}

    # no key leaves the source out of the union, an empty enumeration rather than a call
    monkeypatch.setattr(config, "otx_key", lambda: "")
    assert domains.otx_subdomains("example.com") == set()

    monkeypatch.setattr(config, "otx_key", lambda: "otx")

    class _Resp:
        def __init__(self, payload):
            self._payload = payload

        def read(self):
            return json.dumps(self._payload).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    # a reply at the endpoint cap means more hosts exist unfetched, so it is flagged truncated
    capped = {"passive_dns": [{"hostname": f"h{i}.example.com"} for i in range(500)], "count": 500}
    monkeypatch.setattr(urllib.request, "urlopen", lambda request, timeout=0: _Resp(capped))
    result = domains.otx_subdomains("example.com")
    assert result.truncated is True
    assert len(result) == 500


def test_dnsdumpster_parses_and_flags_the_free_tier_cap(monkeypatch):
    import urllib.request

    from opfor.scenarios.attacksurface import config
    from opfor.scenarios.attacksurface.classes.domain import sources as domains

    # the parse keeps hosts under the domain from the a and cname records, and the domain
    # suffix drops the mail and nameserver records that point off the domain
    reply = {
        "a": [{"host": "api.example.com"}, {"host": "www.example.com"}],
        "cname": [{"host": "cdn.example.com"}],
        "mx": [{"host": "10 aspmx.l.google.com"}],
        "ns": [{"host": "ns-1.awsdns-31.co.uk"}],
        "total_a_recs": "2",
    }
    assert domains.subdomains_from_dnsdumpster(reply, "example.com") == {
        "api.example.com", "www.example.com", "cdn.example.com"}

    # no key leaves the source out of the union, an empty enumeration rather than a call
    monkeypatch.setattr(config, "dnsdumpster_key", lambda: "")
    assert domains.dnsdumpster_subdomains("example.com") == set()

    monkeypatch.setattr(config, "dnsdumpster_key", lambda: "dd")

    class _Resp:
        def __init__(self, payload):
            self._payload = payload

        def read(self):
            return json.dumps(self._payload).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    # the free tier returns fewer a records than the total it reports, so more remain and
    # the reply is flagged truncated rather than passed off as complete
    capped = {"a": [{"host": f"h{i}.example.com"} for i in range(50)], "total_a_recs": "205"}
    monkeypatch.setattr(urllib.request, "urlopen", lambda request, timeout=0: _Resp(capped))
    result = domains.dnsdumpster_subdomains("example.com")
    assert result.truncated is True
    assert len(result) == 50


def test_certspotter_token_429_falls_back_to_an_anonymous_walk(monkeypatch):
    import urllib.error
    import urllib.request

    from opfor.scenarios.attacksurface import config
    from opfor.scenarios.attacksurface.classes.domain import sources as domains

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
    from opfor.scenarios.attacksurface.classes.domain import sources as domains

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
    from opfor.scenarios.attacksurface.classes.domain.sources import roots_from_reverse_whois

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
    from opfor.scenarios.attacksurface.classes.domain.sources import paths_from_openapi

    doc = {"paths": {"/a": {"get": {}, "post": {}}, "/b": {"get": {}}}}
    assert set(paths_from_openapi(doc)) == {"GET,POST /a", "GET /b"}
    assert paths_from_openapi({}) == []
    assert paths_from_openapi({"paths": "not a map"}) == []


def test_operations_from_introspection_reads_query_and_mutation():
    from opfor.scenarios.attacksurface.classes.domain.sources import operations_from_introspection

    data = {"__schema": {"queryType": {"fields": [{"name": "me"}]},
                         "mutationType": {"fields": [{"name": "login"}]}}}
    assert operations_from_introspection(data) == ["mutation:login", "query:me"]
    assert operations_from_introspection({}) == []


def test_subdomains_from_vt_reads_relationship_ids():
    from opfor.scenarios.attacksurface.classes.domain.sources import subdomains_from_vt

    page = {"data": [{"id": "api.example.com"}, {"id": "*.mail.example.com"},
                     {"id": "unrelated.test"}]}
    # a wildcard keeps its star, so the enumeration can flag it rather than lose it
    assert subdomains_from_vt(page, "example.com") == {"api.example.com", "*.mail.example.com"}


def test_virustotal_is_skipped_without_a_key(monkeypatch):
    from opfor.scenarios.attacksurface.classes.domain import sources as d

    monkeypatch.delenv("OPFOR_VIRUSTOTAL_API_KEY", raising=False)
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
    from opfor.scenarios.attacksurface.classes.domain.sources import (
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
    from opfor.scenarios.attacksurface.classes.domain.sources import robots_entries, sitemap_paths

    paths, sitemaps = robots_entries("User-agent: *\nDisallow: /admin\nAllow: /public\nSitemap: https://h/sm.xml")
    assert paths == ["/admin", "/public"]
    assert sitemaps == ["https://h/sm.xml"]
    assert sitemap_paths("<urlset><url><loc>https://h.test/a</loc></url></urlset>", "h.test") == ["/a"]


def test_split_operation_separates_methods_from_path():
    from opfor.scenarios.attacksurface.classes.domain.sources import split_operation

    assert split_operation("GET,POST /widgets") == (("GET", "POST"), "/widgets")
    assert split_operation("DELETE,GET /jobs/{job_id}") == (("DELETE", "GET"), "/jobs/{job_id}")
    assert split_operation("/bare-path") == ((), "/bare-path")


def test_probe_spec_verifies_reads_defers_writes_and_skips_templated():
    """A declared operation is not a reachable one, so ProbeSpec fetches each concrete GET
    and leaves write and templated operations for an authorized confirmation."""
    from opfor.core import Fact, Node, Task, World
    from opfor.scenarios.attacksurface.classes.domain.capabilities import ProbeSpec
    from opfor.scenarios.attacksurface.classes.domain.types import (
        APISpec, DomainData, Endpoint, Resolved,
    )

    calls = []

    def fetch(name, addresses, path):
        calls.append(path)
        if path.startswith("/opfor-baseline") or path.startswith("/does-not-exist"):
            return {"status": 404, "content_type": "", "body": "", "location": ""}
        if path == "/config/all":
            return {"status": 200, "content_type": "application/json",
                    "body": '{"ok":true}', "location": ""}
        if path == "/users":
            return {"status": 401, "content_type": "", "body": "", "location": ""}
        return {"status": 404, "content_type": "", "body": "", "location": ""}

    world = World()
    world.add(Node(id="domain:api.example.com", type="domain",
                   payload=DomainData(name="api.example.com", root="example.com", source="crt")))
    world.absorb([Fact(kind="resolved", about="domain:api.example.com",
                       payload=Resolved(resolvable=True, addresses=("203.0.113.5",), cnames=()))])
    ep_id = "endpoint:api.example.com/openapi.json"
    world.add(Node(id=ep_id, type="endpoint",
                   payload=Endpoint(url="https://api.example.com/openapi.json", path="/openapi.json",
                                    status=200, auth_required=False, content_type="application/json")))
    world.absorb([Fact(kind="api_spec", about=ep_id, payload=APISpec(
        base="https://api.example.com/openapi.json",
        paths=("GET /config/all", "GET /users", "POST /process", "DELETE,GET /jobs/{job_id}"),
        count=4))])

    out = ProbeSpec(fetch).run(Task(capability="endpoint_probe_spec", node=ep_id), world)

    facts = [f for f in out.facts if f.kind == "spec_audit"]
    assert len(facts) == 1
    ops = {op.path: op for op in facts[0].payload.operations}

    assert ops["/config/all"].verified and ops["/config/all"].status == 200
    assert not ops["/config/all"].auth_required and ops["/config/all"].distinct
    assert ops["/users"].verified and ops["/users"].auth_required
    assert not ops["/process"].verified and "write" in ops["/process"].reason
    assert not ops["/jobs/{job_id}"].verified and "templated" in ops["/jobs/{job_id}"].reason
    # A write operation and a templated path are never sent.
    assert "/process" not in calls
    assert "/jobs/{job_id}" not in calls


def test_certspotter_flags_truncation_when_the_page_budget_is_spent(monkeypatch):
    """A walk that spends its whole page budget on full pages leaves later certificates
    unread, so it reports the blind spot rather than passing as complete, invariant 5."""
    import urllib.request

    from opfor.scenarios.attacksurface import config
    from opfor.scenarios.attacksurface.classes.domain import sources as domains

    monkeypatch.setattr(config, "certspotter_token", lambda: "")

    class _Resp:
        def __init__(self, payload):
            self._payload = payload

        def read(self):
            return json.dumps(self._payload).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    # every page is full and carries an id cursor, so the bounded walk never runs dry
    def fake_urlopen(request, timeout=0):
        return _Resp([{"id": "999", "dns_names": ["api.example.com"]}])

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    result = domains.certspotter_subdomains("example.com")
    assert result == {"api.example.com"}
    assert result.truncated is True


def test_certspotter_does_not_flag_truncation_when_the_cursor_runs_dry(monkeypatch):
    import urllib.request

    from opfor.scenarios.attacksurface import config
    from opfor.scenarios.attacksurface.classes.domain import sources as domains

    monkeypatch.setattr(config, "certspotter_token", lambda: "")

    class _Resp:
        def __init__(self, payload):
            self._payload = payload

        def read(self):
            return json.dumps(self._payload).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    # a page with no id cursor ends the walk, so the enumeration is complete
    def fake_urlopen(request, timeout=0):
        return _Resp([{"dns_names": ["api.example.com"]}])

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    result = domains.certspotter_subdomains("example.com")
    assert result.truncated is False


def test_info_from_openapi_reads_title_and_version():
    from opfor.scenarios.attacksurface.classes.domain.sources import info_from_openapi

    doc = {"openapi": "3.1.0", "info": {"title": "litellm api", "version": "1.90.0"}, "paths": {}}
    assert info_from_openapi(doc) == ("litellm api", "1.90.0")
    assert info_from_openapi({"swagger": "2.0", "info": {"title": "x"}}) == ("x", "")
    assert info_from_openapi({"paths": {}}) == ("", "")
    assert info_from_openapi("not a doc") == ("", "")


def test_cve_evidence_surfaces_the_spec_version_from_the_endpoint_body():
    """The CVE identification reads a specification's declared version from the endpoint's
    own body head, before any separate parse runs, so a version-bearing spec is not missed."""
    from opfor.core import Node, Task, World
    from opfor.scenarios.attacksurface.classes.domain.capabilities import CveScan
    from opfor.scenarios.attacksurface.classes.domain.types import DomainData, Endpoint

    captured = {}

    def identify(evidence):
        captured["evidence"] = evidence
        return {"product": "", "version": "", "cpe": ""}

    def cves(product, version, cpe=""):
        return []

    world = World()
    world.add(Node(id="domain:api.example.com", type="domain",
                   payload=DomainData(name="api.example.com", root="example.com", source="crt")))
    ep_id = "endpoint:api.example.com/openapi.json"
    body = '{"openapi":"3.1.0","info":{"title":"litellm api","version":"1.90.0"},"paths":{}}'
    world.add(Node(id=ep_id, type="endpoint",
                   payload=Endpoint(url="https://api.example.com/openapi.json", path="/openapi.json",
                                    status=200, auth_required=False,
                                    content_type="application/json", body=body)))

    out = CveScan(identify, cves).run(Task(capability="cve_scan", node="domain:api.example.com"), world)
    assert out.facts
    assert "1.90.0" in captured["evidence"]
    assert "litellm api" in captured["evidence"]


# --- regression: a 1example-like synthetic surface, the model-independent invariants -------
# These lock what does not depend on the triage model, so they are a deterministic gate.
# The surface is the reserved-domain fixture above, shaped to mirror phenomena a real run
# met: an open spec, a login redirect, a dotenv that answers a shell not a file, a dangling
# subdomain, a wildcard blind spot. Judgment quality needs the real model and lives in the
# live benchmark, not here. Here we only assert closure, the code-minted structural
# findings, grounding integrity, and that reproduce stays read only.


def _read_only(url):
    return {"status": 200, "url": url, "content_type": "text/html", "body": "<html></html>"}


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

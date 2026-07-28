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

from opfor.core import Budget, MockProvider, Node, Scope, World, run
from opfor.scenarios.attacksurface import build
from opfor.scenarios.attacksurface.assets.domain.sources.observations import (
    Liveness,
    Resolution,
    Response,
)
from opfor.scenarios.attacksurface.assets.domain.hostnames import HostScope
from opfor.scenarios.attacksurface.assets.domain.seed import Org

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
    # admin's robots discloses its sensitive paths, so they surface through evidence rather than a
    # blind probe, the only way a leak is reached now that the global probe list is gone.
    "https://admin.example.com/robots.txt": {"status": 200, "body":
        "user-agent: *\ndisallow: /.git/config\ndisallow: /.env\ndisallow: /metrics\ndisallow: /admin"},
}


def _fetch(name, addresses, path, *, body_limit=None):
    url = f"https://{name}{path}"
    if name == "spa.example.com":
        # a single-page app: 200 HTML for every path, but a real JSON spec at one path
        if path == "/openapi.json":
            return Response(status=200, url=url, content_type="application/json",
                            server="cf", body='{"openapi":"3.0.0","paths":{}}')
        return Response(status=200, url=url, content_type="text/html",
                        server="cf", body="<html>spa app single page</html>")
    if name == "cf.example.com":
        # a host that serves an empty 200 for /.env, the shape that used to false-positive
        if path == "/.env":
            return Response(status=200, url=url, server="cf")
        return Response(status=404, url=url)
    d = ENDPOINTS.get(url, {"status": 404, "body": ""})
    return Response(status=d["status"], url=url, content_type=d.get("ct", ""),
                    server=d.get("server", ""), body=d["body"].lower(),
                    location=d.get("loc", ""))



# A full document fetch, the app declaring itself. spa serves an OpenAPI spec, admin serves
# a home page linking a JavaScript bundle that hardcodes an API path only readable from it.
def _fetch_doc(name, path):
    if name == "spa.example.com" and path == "/openapi.json":
        return Response(status=200, content_type="application/json",
                        body='{"openapi":"3.0.0","paths":{"/users":{"get":{}},"/orders":{"get":{},"post":{}}}}')
    if name == "admin.example.com" and path == "/":
        return Response(status=200, content_type="text/html",
                        body='<html><body><script src="/app.js"></script></body></html>')
    if name == "admin.example.com" and path == "/app.js":
        return Response(status=200, content_type="application/javascript",
                        body=('const API="/api";fetch("/api/secret");const css="/main.css";'
                              'fetch("/portal");fetch("/private");'
                              'fetch("https://api.example.com/v2/balance");'))
    return Response(status=None)


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
    d = DNS.get(name, {"resolvable": False, "addresses": ()})
    return Resolution(resolvable=d["resolvable"], addresses=d.get("addresses", ()),
                      cnames=d.get("cnames", ()))


def _probe(name, addresses=()):
    d = HTTP.get(name, {"alive": False})
    return Liveness(alive=d["alive"], status=d.get("status"), url=d.get("url", ""),
                    server=d.get("server", ""), title=d.get("title", ""), body=d.get("body", ""),
                    location=d.get("location", ""), headers=d.get("headers", ()))


def _identify(evidence):
    # By default nothing is identified, so the cve scan is a quiet no-op and never touches
    # the triage MockProvider. A test that drives a product overrides this seam.
    return {"product": "", "version": "", "cpe": ""}


def _cves(product, version, cpe=""):
    return []


def _make(**over):
    """Build the scenario with every seam faked, so no test touches the network or the
    model. A MockProvider stands in for the triage model, returning an empty result by
    default. A test overrides one seam to drive a failure or a variant, or passes its own
    provider to drive a canned model reply."""
    seams = dict(enumerate_fn=_enumerate,
                 resolve_fn=_resolve, probe_fn=_probe, fetch_fn=_fetch, fetch_doc_fn=_fetch_doc,
                 introspect_fn=_introspect, wayback_fn=_wayback, identify_fn=_identify, cve_fn=_cves)
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


# A test drives a transient failure to prove the run still closes and is loud, so the engine
# retries it. The backoff is zeroed so those retries do not sleep in the suite.
def _run(world, scope=None, budget=500):
    return run(_scenario(), world,
               scope=scope or Scope(max_tier="recon", matcher=HostScope(hosts=(ROOT,))),
               budget=Budget(budget), retry_backoff=0.0)


def _run_capturing(world=None, *, scope=None, budget=2000, **over):
    """Run the full pipeline and return the report and the scenario, so a test can read the
    surface prompt the triage model was given off `scenario.triage._provider`."""
    scenario = _make(**over)
    world = world if world is not None else _seed()
    report = run(scenario, world,
                 scope=scope or Scope(max_tier="recon", matcher=HostScope(hosts=(ROOT,))),
                 budget=Budget(budget), retry_backoff=0.0)
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


def _two_findings():
    return json.dumps({"findings": [
        {"category": "missing-authentication", "title": "Exposed admin", "severity": "HIGH",
         "where": "https://a/.git/config", "evidence": "core section present"},
        {"category": "improper-authentication", "title": "Login redirect", "severity": "INFO",
         "where": "https://a/portal", "evidence": "302 to /login"},
    ]})


__all__ = [
    'ROOT',
    'HostScope',
    'CRT',
    'DNS',
    'HTTP',
    'ENDPOINTS',
    '_fetch',
    '_fetch_doc',
    '_introspect',
    '_wayback',
    '_enumerate',
    '_resolve',
    '_probe',
    '_identify',
    '_cves',
    '_make',
    '_scenario',
    '_seed',
    '_run',
    '_run_capturing',
    '_prompt',
    '_knowledge',
    '_two_findings',
]

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
from opfor.scenarios.attacksurface.lifecycle.triage import TriageError, _finding_from_dict
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


def _dns(domain):
    # By default a root sets no email authentication and no CAA and is unsigned, so the posture
    # scan surfaces the absences. A test overrides this seam to drive a configured domain.
    return {"spf": (), "dmarc": "", "caa": (), "dnssec": False}


def _tls(name, addresses=()):
    # By default a host serves a valid certificate over a modern protocol, so the TLS scan is a
    # quiet clean result. A test overrides this seam to drive an expired or untrusted cert.
    return {"reachable": True, "valid": True, "validity_error": "", "not_after": "",
            "days_to_expiry": 300, "protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384"}


def _ports(name, addresses=()):
    # By default a host exposes no sensitive service port, so the scan is a quiet clean result.
    # A test overrides this seam to drive an exposed database or management service.
    return {"reachable": True, "scanned": 24, "open": []}


def _make(**over):
    """Build the scenario with every seam faked, so no test touches the network or the
    model. A MockProvider stands in for the triage model, returning an empty result by
    default. A test overrides one seam to drive a failure or a variant, or passes its own
    provider to drive a canned model reply."""
    seams = dict(search_fn=_search, repos_fn=_repos, enumerate_fn=_enumerate, pivot_fn=_pivot,
                 resolve_fn=_resolve, probe_fn=_probe, fetch_fn=_fetch, fetch_doc_fn=_fetch_doc,
                 introspect_fn=_introspect, wayback_fn=_wayback, identify_fn=_identify, cve_fn=_cves,
                 probe_url_fn=_probe_url, dns_fn=_dns, tls_fn=_tls, ports_fn=_ports)
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


def _claim(fid, *, severity="MEDIUM", where="https://h/x", title="t"):
    from opfor.core import Finding
    # A grounded finding carries the request grounding matched, so confirm binds its receipt by
    # url rather than by id alone. The url is the one the receipt fixtures replay.
    return Finding(id=fid, title=title, severity=severity, where=where,
                   evidence="judged from the report", poc=f"safe read: curl -s {where}",
                   data={"poc_request": {"method": "GET", "url": where}})

def _receipt(**over):
    from opfor.scenarios.attacksurface.lifecycle.reproduce import Reproduction
    fields = dict(method="GET", url="https://h/x", status=200,
                  content_type="application/json", size=12, excerpt='{"ok": true}', error="")
    fields.update(over)
    return Reproduction(**fields)

def _two_findings():
    return json.dumps({"findings": [
        {"category": "sensitive-file-exposure", "title": "Exposed .git", "severity": "HIGH",
         "where": "https://a/.git/config", "evidence": "core section present"},
        {"category": "unauthenticated-interface", "title": "Login redirect", "severity": "INFO",
         "where": "https://a/portal", "evidence": "302 to /login"},
    ]})

def _with_reverse(reverse_fn=_reverse):
    return _make(reverse_whois_fn=reverse_fn)

def _read_only(url):
    return {"status": 200, "url": url, "content_type": "text/html", "body": "<html></html>"}


__all__ = [
    'ROOT',
    'CRT',
    'DNS',
    'HTTP',
    'GH_ORGS',
    'GH_REPOS',
    '_search',
    '_repos',
    'ENDPOINTS',
    '_fetch',
    'SIBLINGS',
    '_pivot',
    'WHOIS',
    '_reverse',
    '_fetch_doc',
    '_introspect',
    '_wayback',
    '_enumerate',
    '_resolve',
    '_probe',
    '_identify',
    '_cves',
    '_probe_url',
    '_dns',
    '_tls',
    '_ports',
    '_make',
    '_scenario',
    '_seed',
    '_run',
    '_run_capturing',
    '_prompt',
    '_knowledge',
    '_claim',
    '_receipt',
    '_two_findings',
    '_with_reverse',
    '_read_only',
]

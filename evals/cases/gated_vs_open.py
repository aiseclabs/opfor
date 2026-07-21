"""gated-vs-open: an open admin interface to catch, two gated hosts not to flag as open.

This is the distinction that dominated a real run. Most internal services sit correctly
behind a per-request identity proxy or an application SSO and are not an open surface, judged
an informational gated host. A finding that calls a gated host an open unauthenticated
interface is the false positive. One host here is genuinely open, the admin panel to catch.

A gated host does draw a correct informational gated finding, so the safe entries guard the
open class only, with a category, so the right gated verdict is uncounted and only a wrong
open-interface verdict on a gated host scores a false positive.
"""

from __future__ import annotations

from opfor.core import Node, World
from opfor.scenarios.attacksurface.types import Org
from evals.schema import answer_key_from_dict

NAME = "gated-vs-open"
ROOT = "example.com"
SCOPE_HOSTS = (ROOT,)

_HOSTS = {"open-admin.example.com", "iap.example.com", "sso.example.com"}

_DNS = {
    "example.com": {"resolvable": True, "addresses": ("1.1.1.1",)},
    "open-admin.example.com": {"resolvable": True, "addresses": ("1.1.1.2",)},
    "iap.example.com": {"resolvable": True, "addresses": ("1.1.1.3",)},
    "sso.example.com": {"resolvable": True, "addresses": ("1.1.1.4",)},
}

_HTTP = {
    "example.com": {"alive": True, "status": 200, "url": "https://example.com/", "server": "nginx",
                    "title": "home", "body": "welcome"},
    # a genuinely open admin panel, reachable with no authentication
    "open-admin.example.com": {"alive": True, "status": 200, "url": "https://open-admin.example.com/",
                               "server": "nginx", "title": "Admin Dashboard",
                               "body": "admin dashboard: manage users, api keys, and settings, no authentication required"},
    # gated by a Google Cloud Identity-Aware Proxy, a per-request identity proxy
    "iap.example.com": {"alive": True, "status": 302, "url": "https://iap.example.com/",
                        "server": "Google Frontend", "title": "", "body": "invalid iap credentials: empty token",
                        "location": "https://accounts.google.com/o/oauth2/v2/auth?client_id=iap",
                        "headers": [("x-goog-iap-generated-response", "true")]},
    # gated by an application single sign-on, a routed login redirect
    "sso.example.com": {"alive": True, "status": 302, "url": "https://sso.example.com/",
                        "server": "nginx", "title": "", "body": "redirecting to sign in",
                        "location": "https://sso.example.com/sso/login"},
}


def _search(name, token=""):
    return []


def _repos(login, token=""):
    return []


def _enumerate(domain):
    return set(_HOSTS) if domain == ROOT else set()



def _resolve(name):
    return _DNS.get(name, {"resolvable": False, "addresses": ()})


def _probe(name, addresses=()):
    return dict(_HTTP.get(name, {"alive": False, "status": None, "url": "", "server": "",
                                 "title": "", "body": ""}))


def _fetch(name, addresses, path):
    url = f"https://{name}{path}"
    if name == "open-admin.example.com" and path == "/admin":
        return {"status": 200, "url": url, "content_type": "text/html", "server": "nginx",
                "title": "Admin", "body": "admin dashboard: users, settings"}
    return {"status": 404, "url": url, "content_type": "", "server": "", "title": "", "body": ""}


def _fetch_doc(name, path):
    return {"status": None, "content_type": "", "text": ""}


def _introspect(name, path="/graphql"):
    return None


def _wayback(host):
    return set()


def _probe_url(url):
    return {"status": 404, "url": url, "content_type": "", "body": ""}


def _identify(evidence):
    return {"product": "", "version": "", "cpe": ""}


def _cves(product, version, cpe=""):
    return []


def seams() -> dict:
    return dict(search_fn=_search, repos_fn=_repos, enumerate_fn=_enumerate,
                resolve_fn=_resolve, probe_fn=_probe, fetch_fn=_fetch, fetch_doc_fn=_fetch_doc,
                introspect_fn=_introspect, wayback_fn=_wayback, probe_url_fn=_probe_url,
                identify_fn=_identify, cve_fn=_cves)


def world() -> World:
    w = World()
    w.add(Node(id="org:ExampleCorp", type="org",
               payload=Org(name="ExampleCorp", domains=(ROOT,), hosts=(), classes=())))
    return w


def answer_key():
    return answer_key_from_dict({
        "target": NAME,
        "planted": [
            {"id": "open-admin", "where": "open-admin.example.com",
             "note": "an admin panel is reachable with no authentication"},
        ],
        "safe": [
            {"id": "iap-gated", "where": "iap.example.com", "category": "unauthenticated-interface",
             "note": "gated by a Google Cloud IAP, a correct gated verdict is informational, not open"},
            {"id": "sso-gated", "where": "sso.example.com", "category": "unauthenticated-interface",
             "note": "gated by an application SSO redirect, not an open interface"},
        ],
    })

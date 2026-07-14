"""graphql-introspection: an open introspection to catch, a closed endpoint not to flag.

One host answers a GraphQL introspection query with its full schema, the exposure to catch.
Another host serves a GraphQL endpoint that refuses introspection, the safe lookalike a run
must not flag, since a reachable endpoint alone is not the finding, an open schema is.
"""

from __future__ import annotations

from opfor.core import Node, World
from opfor.scenarios.attacksurface.types import Org
from evals.schema import answer_key_from_dict

NAME = "graphql-introspection"
ROOT = "example.com"
SCOPE_HOSTS = (ROOT,)

_HOSTS = {"open-gql.example.com", "closed-gql.example.com"}

_DNS = {
    "example.com": {"resolvable": True, "addresses": ("1.1.1.1",)},
    "open-gql.example.com": {"resolvable": True, "addresses": ("1.1.1.2",)},
    "closed-gql.example.com": {"resolvable": True, "addresses": ("1.1.1.3",)},
}

_HTTP = {
    "example.com": {"alive": True, "status": 200, "url": "https://example.com/", "server": "nginx",
                    "title": "home", "body": "welcome"},
    "open-gql.example.com": {"alive": True, "status": 200, "url": "https://open-gql.example.com/",
                             "server": "apollo", "title": "api", "body": "ok"},
    "closed-gql.example.com": {"alive": True, "status": 200, "url": "https://closed-gql.example.com/",
                               "server": "apollo", "title": "api", "body": "ok"},
}

_SCHEMA = {"__schema": {"queryType": {"name": "Query", "fields": [{"name": "me"}, {"name": "users"}]},
                        "mutationType": {"name": "Mutation", "fields": [{"name": "login"}, {"name": "deleteUser"}]}}}


def _search(name, token=""):
    return []


def _repos(login, token=""):
    return []


def _enumerate(domain):
    return set(_HOSTS) if domain == ROOT else set()


def _pivot(domain):
    return {}


def _resolve(name):
    return _DNS.get(name, {"resolvable": False, "addresses": ()})


def _probe(name, addresses=()):
    return dict(_HTTP.get(name, {"alive": False, "status": None, "url": "", "server": "",
                                 "title": "", "body": ""}))


def _fetch(name, addresses, path):
    url = f"https://{name}{path}"
    if path == "/graphql" and name in _HOSTS:
        # both hosts serve a reachable GraphQL endpoint, only one answers introspection
        return {"status": 200, "url": url, "content_type": "application/json", "server": "apollo",
                "title": "", "body": '{"data":{}}'}
    return {"status": 404, "url": url, "content_type": "", "server": "", "title": "", "body": ""}


def _fetch_doc(name, path):
    return {"status": None, "content_type": "", "text": ""}


def _introspect(name, path="/graphql"):
    if name == "open-gql.example.com":
        return dict(_SCHEMA)
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
    return dict(search_fn=_search, repos_fn=_repos, enumerate_fn=_enumerate, pivot_fn=_pivot,
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
            {"id": "open-introspection", "where": "open-gql.example.com",
             "category": "graphql-introspection",
             "note": "the endpoint answers an introspection query with its full schema"},
        ],
        "safe": [
            {"id": "closed-introspection", "where": "closed-gql.example.com",
             "category": "graphql-introspection",
             "note": "the endpoint is reachable but refuses introspection, so it is not the finding"},
        ],
    })

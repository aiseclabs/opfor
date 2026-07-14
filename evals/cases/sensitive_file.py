"""sensitive-file: a real config leak to catch, an app shell not to flag.

One host leaks a git config and a dotenv with real key-value lines, the true exposure to
catch. Another host answers its app shell for every path, including the dotenv path, the safe
lookalike a run must not read as a leak. This is the positive side the openspec-min case only
had the safe half of, so the two together pin both a real catch and a non-catch on the
sensitive-file axis.
"""

from __future__ import annotations

from opfor.core import Node, World
from opfor.scenarios.attacksurface.types import Org
from evals.schema import answer_key_from_dict

NAME = "sensitive-file"
ROOT = "example.com"
SCOPE_HOSTS = (ROOT,)

_HOSTS = {"leak.example.com", "shell.example.com"}

_DNS = {
    "example.com": {"resolvable": True, "addresses": ("1.1.1.1",)},
    "leak.example.com": {"resolvable": True, "addresses": ("1.1.1.2",)},
    "shell.example.com": {"resolvable": True, "addresses": ("1.1.1.3",)},
}

_HTTP = {
    "example.com": {"alive": True, "status": 200, "url": "https://example.com/", "server": "nginx",
                    "title": "home", "body": "welcome"},
    "leak.example.com": {"alive": True, "status": 200, "url": "https://leak.example.com/",
                         "server": "nginx", "title": "app", "body": "ok"},
    "shell.example.com": {"alive": True, "status": 200, "url": "https://shell.example.com/",
                          "server": "cloudflare", "title": "app", "body": "<html>app shell</html>"},
}

_GIT_CONFIG = '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://example.com/acme/app.git'
_DOTENV = "db_password=s3cr3t_value\napi_key=abcdef0123456789\nsecret_token=zyxw9876"


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
    if name == "leak.example.com":
        if path == "/.git/config":
            return {"status": 200, "url": url, "content_type": "text/plain", "server": "nginx",
                    "title": "", "body": _GIT_CONFIG}
        if path == "/.env":
            return {"status": 200, "url": url, "content_type": "text/plain", "server": "nginx",
                    "title": "", "body": _DOTENV}
        return {"status": 404, "url": url, "content_type": "", "server": "", "title": "", "body": ""}
    if name == "shell.example.com":
        # an app shell for every path, so the dotenv probe returns html not a file
        return {"status": 200, "url": url, "content_type": "text/html", "server": "cloudflare",
                "title": "", "body": "<html>app shell</html>"}
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
            {"id": "config-leak", "where": "leak.example.com",
             "note": "a git config and a dotenv with real key-value lines are readable"},
        ],
        "safe": [
            {"id": "shell-dotenv", "where": "https://shell.example.com/.env",
             "category": "sensitive-file-exposure",
             "note": "the dotenv path returns the app shell, not a file, so it is not a leak"},
        ],
    })

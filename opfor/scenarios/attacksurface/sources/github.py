"""GitHub-class sources: find orgs by name, then list an org's public repos.

The GitHub public API answers both from an org name alone, which is how the run goes
from a bare company name to an asset. It works unauthenticated at a low rate, a token
from the environment raises the limit. A non-success status is raised, never turned
into an empty result.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request

_API = "https://api.github.com"
_UA = "opfor-attacksurface"


def _get(path: str, token: str) -> object:
    headers = {"User-Agent": _UA, "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(_API + path, headers=headers)
    with urllib.request.urlopen(request, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def search_orgs(name: str, token: str = "", *, limit: int = 10) -> list[dict]:
    """GitHub organizations whose account matches the name, best match first.

    The query restricts to org accounts, so a personal user with the name does not
    pollute the result. The token stays in the request header, never in a returned value.
    """
    query = urllib.parse.urlencode({"q": f"{name} type:org", "per_page": str(limit)})
    body = _get(f"/search/users?{query}", token)
    items = body.get("items", []) if isinstance(body, dict) else []
    return [
        {"login": str(i.get("login", "")), "url": str(i.get("html_url", "")), "org_id": i.get("id")}
        for i in items if i.get("login")
    ]


def org_repos(login: str, token: str = "", *, limit: int = 100) -> list[dict]:
    """Public repositories under an org, most recently pushed first."""
    query = urllib.parse.urlencode({"per_page": str(limit), "sort": "pushed"})
    body = _get(f"/orgs/{urllib.parse.quote(login)}/repos?{query}", token)
    rows = body if isinstance(body, list) else []
    return [
        {
            "full_name": str(r.get("full_name", "")),
            "url": str(r.get("html_url", "")),
            "language": str(r.get("language") or ""),
            "pushed_at": str(r.get("pushed_at") or ""),
            "archived": bool(r.get("archived")),
        }
        for r in rows if r.get("full_name")
    ]

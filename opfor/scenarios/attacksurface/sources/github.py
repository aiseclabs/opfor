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
    """GitHub organizations whose account matches the name, each with its attribution
    evidence, best match first.

    The query restricts to org accounts, so a personal user with the name does not
    pollute the result. A name match alone does not prove ownership, so each candidate's
    public profile is fetched for the website and email that tie it to a domain, the
    evidence attribution needs. A profile that will not load leaves those fields empty,
    so one bad profile does not drop the candidate. The token stays in the request header,
    never in a returned value.
    """
    query = urllib.parse.urlencode({"q": f"{name} type:org", "per_page": str(limit)})
    body = _get(f"/search/users?{query}", token)
    items = body.get("items", []) if isinstance(body, dict) else []
    out: list[dict] = []
    for item in items:
        login = str(item.get("login", ""))
        if not login:
            continue
        profile: dict = {}
        try:
            fetched = _get(f"/orgs/{urllib.parse.quote(login)}", token)
            profile = fetched if isinstance(fetched, dict) else {}
        except Exception:
            profile = {}
        out.append({
            "login": login,
            "url": str(item.get("html_url", "")),
            "org_id": item.get("id"),
            "name": str(profile.get("name") or ""),
            "blog": str(profile.get("blog") or ""),
            "email": str(profile.get("email") or ""),
            "verified": bool(profile.get("is_verified")),
        })
    return out


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

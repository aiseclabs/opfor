"""Company name to candidate root domains, the propose half of root discovery.

A company name is not a domain, so the first move is a guess: several free sources each propose
roots named after the org, a name-matched GitHub org, an npm scope, a PyPI package, a crt.sh
organization search. Every one is a name match, which only names a namesake, an unrelated maker
space shares a prefix, so no source confirms ownership on its own. Each proposal is a candidate the
confirmer must tie to a known root by certificate co-tenancy or registrant before it is scanned.
Every source is an injected seam, so a test drives the composer with fixtures, and one source
failing degrades to a coverage gap rather than the run.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from opfor.scenarios.attacksurface.hostnames import looks_like_host, registrable_root
from opfor.scenarios.attacksurface.assets.domain.sources.dns import _JSON_LIMIT, _TIMEOUT, _UA
from opfor.scenarios.attacksurface.assets.domain.sources.passive import (
    _crtsh_org_certs,
    roots_from_crtsh_org,
)
from opfor.scenarios.attacksurface.assets.domain.types import ProposalResult, RootCandidate


# Public hosting and mail providers are shared by everyone, so a domain under one is not the
# org's own root and is dropped from a proposal rather than proposed as a candidate.
_SHARED_SUFFIXES = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "yahoo.com", "qq.com",
    "163.com", "protonmail.com", "icloud.com",
    "github.com", "gitlab.com", "bitbucket.org", "sourceforge.net", "gitee.com",
    "github.io", "gitlab.io", "herokuapp.com", "netlify.app", "vercel.app", "pages.dev",
    "readthedocs.io", "readthedocs.org", "pypi.org", "npmjs.com",
    "wordpress.com", "blogspot.com", "medium.com",
})


def _root_from_value(value: str) -> str:
    """The registrable root of a url or bare host, or empty when it is not a usable host."""
    value = value.strip().lower()
    if not value:
        return ""
    if "://" in value:
        value = urllib.parse.urlsplit(value).netloc
    value = value.split("/")[0].split("@")[-1].split(":")[0].lstrip("*.")
    if not looks_like_host(value):
        return ""
    root = registrable_root(value)
    return "" if root in _SHARED_SUFFIXES else root


def crtsh_org_roots(name: str, terms: tuple[str, ...] = ()) -> list[RootCandidate]:
    """Candidate roots from certificates whose subject organization matches the name, a name match.

    The subject-organization field is loose and shared, so a match names a candidate, never proof.
    One light query per term, not the paged walk crt.sh was dropped from for subdomains.
    """
    out: list[RootCandidate] = []
    seen: set[str] = set()
    for term in (name, *terms):
        term = term.strip()
        if not term:
            continue
        for root, signal in roots_from_crtsh_org(_crtsh_org_certs(term), term).items():
            if root not in seen:
                seen.add(root)
                out.append(RootCandidate(name=root, source="crtsh-org", signal=signal))
    return out


def github_declared_roots(name: str, search_fn) -> list[RootCandidate]:
    """Candidate roots a name-matched GitHub org declares, its website and contact email.

    The org is matched by name, so it may be a namesake, and even a GitHub-verified org has only
    proven its own domain, not that it is the target. So the root is a candidate the confirmer must
    prove. The verified flag rides in the signal for the record. Same search seam the class uses.
    """
    out: list[RootCandidate] = []
    seen: set[str] = set()
    for profile in search_fn(name):
        verified = ", a GitHub-verified org" if profile.get("verified") else ""
        for field in ("blog", "email"):
            root = _root_from_value(str(profile.get(field, "")))
            if root and root not in seen:
                seen.add(root)
                out.append(RootCandidate(name=root, source="github",
                                         signal=f"named on the GitHub org {profile.get('login', '')!r} "
                                                f"{field}{verified}"))
    return out


def pypi_org_roots(name: str) -> list[RootCandidate]:
    """Candidate roots from the project urls of a PyPI package named after the org.

    PyPI offers no free search by company, so this reads the package named for the org, an exact
    name tie, and takes the domains it declares. It is narrow by design, a company that publishes
    no same-named package yields nothing, but it never fudges a search PyPI does not offer. A 404
    is no package, not a source failure, so it is skipped rather than raised.
    """
    out: list[RootCandidate] = []
    seen: set[str] = set()
    slug = name.strip().lower()
    for candidate_slug in dict.fromkeys([slug, slug.replace(" ", "-"), slug.replace(" ", "")]):
        if not candidate_slug:
            continue
        info = _pypi_project(candidate_slug)
        urls = [str(info.get("home_page") or "")]
        urls += [str(v or "") for v in (info.get("project_urls") or {}).values()]
        for url in urls:
            root = _root_from_value(url)
            if root and root not in seen:
                seen.add(root)
                out.append(RootCandidate(name=root, source="pypi",
                                         signal=f"project url of the PyPI package {candidate_slug!r}"))
    return out


def npm_org_roots(name: str) -> list[RootCandidate]:
    """Candidate roots from the homepages of packages under the org's exact npm scope.

    Only a package whose scope is the org name is read, so a text match on an unrelated package
    does not widen the proposal. An exact scope is a strong name tie, but still a name tie, so the
    root is a candidate the confirmer must prove.
    """
    out: list[RootCandidate] = []
    seen: set[str] = set()
    scope = name.strip().lower().replace(" ", "")
    for pkg in _npm_search(name):
        package = pkg.get("package", {}) if isinstance(pkg, dict) else {}
        if str(package.get("scope", "")).lower() != scope:
            continue
        links = package.get("links", {}) if isinstance(package, dict) else {}
        root = _root_from_value(str(links.get("homepage", "")))
        if root and root not in seen:
            seen.add(root)
            out.append(RootCandidate(name=root, source="npm",
                                     signal=f"homepage of the npm package {package.get('name', '')!r}"))
    return out


def propose_roots(name: str, terms: tuple[str, ...], *, sources) -> ProposalResult:
    """Union the proposals of every source, first source winning a duplicate, one failing tolerated.

    A source that raises is recorded as a failed source, so a proposal built from a subset is a
    coverage gap the run reports rather than a clean negative, invariant 5. Every candidate is a
    name match the confirmer must prove, so the union order only decides whose signal is recorded.
    """
    by_root: dict[str, RootCandidate] = {}
    failed: list[str] = []
    for label, fetch in sources:
        try:
            proposed = fetch()
        except Exception as exc:
            failed.append(f"{label} {type(exc).__name__}")
            continue
        for candidate in proposed:
            by_root.setdefault(candidate.name, candidate)
    return ProposalResult(candidates=tuple(by_root.values()), failed=tuple(failed))


def _api_json(url: str) -> object:
    request = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=_TIMEOUT) as resp:
        return json.loads(resp.read(_JSON_LIMIT).decode("utf-8", "replace"))


def _pypi_project(slug: str) -> dict:
    """The info block of a PyPI package, empty for a 404, raising on a real transport error."""
    url = f"https://pypi.org/pypi/{urllib.parse.quote(slug)}/json"
    try:
        body = _api_json(url)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {}
        raise
    return body.get("info", {}) if isinstance(body, dict) else {}


def _npm_search(name: str) -> list:
    query = urllib.parse.urlencode({"text": name, "size": "20"})
    body = _api_json(f"https://registry.npmjs.org/-/v1/search?{query}")
    return body.get("objects", []) if isinstance(body, dict) else []

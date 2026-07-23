"""Post-triage grounding: attach a reproducible request to a finding and materialize it.

Triage judges the surface into findings and mutates nothing. This step runs once after
TRIAGE and does the two deterministic things that are not judgment. It matches a finding's
safe-read proof of concept against the GETs the surface actually recorded, and when one
matches it carries the observed receipt into the finding's data and materializes the finding
as a world node, so the read-only reproduce phase has a grounded request to replay.

Strict grounding, so a request no capability made is never marked reproducible. A model can
phrase a proof of concept for a request that was never sent, so the url it names is matched
against the recorded GETs, a host root probe, an endpoint probe, or a verified specification
operation. A finding whose proof of concept needs an attack, a write or an exploit, is never
grounded here, since replaying it would not be a safe read. The step mints no finding and
drops none, so the surface a run reports is unchanged in count, and it never mutates a
finding in place, a grounded finding is a new object with the observed receipt in its data.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit

from opfor.core import Finding, Node, World, iter_md_docs
from opfor.core import Grounding
from opfor.scenarios.attacksurface.lifecycle.reproduce import FindingClaim, PoCRequest
from opfor.scenarios.attacksurface.assets.domain.nuclei_chain import chain_summary

_URL_RE = re.compile(r"https?://[^\s;'\"`)>]+")
# The CVE ids a finding names, so a recipe is grounded only on the finding that actually claims its
# CVE, never stapled onto a more severe finding about a different CVE it cannot demonstrate.
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _cited_cves(finding) -> set[str]:
    """The CVE ids a finding names across its title, evidence, and PoC, upper-cased."""
    text = " ".join((finding.title, finding.evidence, finding.poc))
    return {match.group(0).upper() for match in _CVE_RE.finditer(text)}


def _primary_cve(finding) -> str:
    """The CVE a finding is chiefly about, its title's first CVE, else its first cited one. Grounding
    binds to this, so a recipe matches the finding's own claim and a secondary CVE mentioned in the
    evidence cannot hijack the finding onto a different recipe, a file read stapled onto an RCE."""
    in_title = _CVE_RE.findall(finding.title)
    if in_title:
        return in_title[0].upper()
    cited = sorted(_cited_cves(finding))
    return cited[0] if cited else ""

# The one finding class a recipe reproduces, so the grounder matches a recipe only against the
# known-vulnerability finding that names a CVE, never against an unrelated class.
_KNOWN_VULN = "known-vulnerability"
# The lookup basis a recipe is allowed to fire on, the database tied the CVE to the running
# version, so a recipe is never replayed against a product-wide or name-only match it may not
# affect. The value mirrors the `match` tag the CVE source records.
_VERSION_MATCH = "version"


@dataclass(frozen=True, kw_only=True)
class ReproductionRecipe:
    """One CVE's recorded reproduction, the exact request that demonstrates it and the marker its
    response bears when the instance is affected. A read-only recipe is a GET, a state-changing one
    carries a write method and a body and is replayed only at the exploit tier. It is data read from
    a vendored template or a product's frontmatter, so adding one is a knowledge change and no attack
    decision lives in code, invariant 1."""

    cve: str
    method: str
    path: str
    expect: str
    # The request body a state-changing recipe carries, empty for a read-only GET recipe.
    body: str = ""


def load_reproductions(directory) -> tuple[ReproductionRecipe, ...]:
    """The reproduction recipes carried in the `reproductions` frontmatter of the product files
    under `fingerprints/products/`, since a CVE reproduction is specific to the product it targets
    and lives with that product's own knowledge, not with the generic judgment class. An entry with
    no CVE id is skipped, so a malformed recipe adds nothing rather than grounding on an empty id."""
    out: list[ReproductionRecipe] = []
    for _path, meta, _body in iter_md_docs(Path(directory)):
        for entry in (meta.get("reproductions") or []):
            cve = str(entry.get("id", "")).strip()
            if not cve:
                continue
            out.append(ReproductionRecipe(
                cve=cve, method=str(entry.get("method", "GET")).strip() or "GET",
                path=str(entry.get("path", "")).strip(),
                expect=str(entry.get("expect", "")).strip(),
                body=str(entry.get("body", "")).strip()))
    return tuple(out)


def _urls_in(text: str) -> list[str]:
    """The http urls a proof-of-concept string names, in order, so a finding's request can
    be matched to a recorded observation. Trailing punctuation the regex catches is trimmed."""
    return [m.rstrip(".,") for m in _URL_RE.findall(text or "")]


def _norm_url(url: str) -> str:
    """A url reduced for matching, lowercased scheme and host, no fragment, and no trailing
    slash, so a proof of concept and an observation of the same request compare equal despite
    cosmetic differences. The query is kept, normalized by sorting, so a proof of concept that
    names a query parameter does not match a query-less observed request, which would ground a
    finding in a materially different request. Observed GETs carry no query, so a query-bearing
    proof of concept simply stays ungrounded rather than grounding wrong."""
    parts = urlsplit(url.strip())
    host = parts.hostname or ""
    path = parts.path.rstrip("/")
    query = "?" + urlencode(sorted(parse_qsl(parts.query))) if parts.query else ""
    return f"{parts.scheme.lower()}://{host.lower()}{path}{query}"


class FindingGrounder(Grounding):
    """Ground each finding on a reproducible request, then materialize the grounded ones as world
    nodes for the reproduce phase.

    A finding grounds on one of two sources. When the asset is unknown the only ground is a request
    the surface already observed, a safe read replayed later, strict so a request no capability made
    is never reproducible. When the asset is a known product at a version, a CVE the lookup tied to
    that version has a recorded read-only reproduction, so the finding grounds on the recipe's
    request directly, the request that demonstrates that CVE, without having observed it first. The
    recipe source fires only under the intrusive EXPLOIT phase, so the default recon run replays
    only observed reads.
    """

    def __init__(self, reproductions: tuple[ReproductionRecipe, ...] = (),
                 chains: tuple = ()) -> None:
        # Keyed by upper-cased CVE id, so a lookup record and a recipe match regardless of case.
        self._recipes = {r.cve.upper(): r for r in reproductions}
        self._chains = {c.cve.upper(): c for c in chains}

    def run(self, world: World, findings: tuple[Finding, ...]) -> list[Finding]:
        observed = self._observed_gets(world)
        out: list[Finding] = []
        for finding in findings:
            # Prefer an observed safe read, the recon-tier ground. Fall to a recipe only when the
            # finding names a known vulnerability whose CVE the lookup tied to the running version.
            request = self._poc_request(finding, observed)
            chain = None
            if request is None:
                request = self._recipe_request(finding, world)
            if request is None:
                request, chain = self._chain_request(finding, world)
            if request is None:
                out.append(finding)
                continue
            grounded = replace(finding, data={**finding.data, "poc_request": request})
            # Only a grounded finding becomes a node, so the reproduce step never sees an
            # ungrounded claim. The node is materialized here, never inside triage.
            world.add(Node(id=grounded.id, type="finding", payload=FindingClaim(
                finding_id=grounded.id, title=grounded.title, severity=grounded.severity,
                where=grounded.where, request=PoCRequest(**request), chain=chain)))
            out.append(grounded)
        return out

    def _poc_request(self, finding: Finding, observed: dict) -> dict | None:
        """The reproducible GET a finding's safe-read proof of concept names, or None. The
        url is taken from the proof of concept itself, never from the finding's location, so
        the reproduce phase replays exactly the request the finding claims rather than a
        different one that merely shares a host. The url must match a recorded observation,
        and an exploit-tier proof of concept, one the model marked as needing authorization,
        is never reproducible by a safe read."""
        poc = finding.poc or ""
        if not poc or "authorized exploitation" in poc.lower():
            return None
        for url in _urls_in(poc):
            receipt = observed.get(_norm_url(url))
            if receipt is not None:
                expect = f"HTTP {receipt['status']}"
                if receipt.get("content_type"):
                    expect += f" {receipt['content_type']}"
                return {"method": "GET", "url": url.strip(), "expect": expect,
                        "source": receipt["source"]}
        return None

    def _recipe_request(self, finding: Finding, world: World) -> dict | None:
        """The recipe-sourced request for a known-vulnerability finding, or None. The finding must
        name the known-vulnerability class, and its host must carry a CVE the lookup matched to the
        running version, since a recipe is never replayed against a product-wide or name-only match.
        The request url is built from the recipe path against the host's observed scheme and
        authority, not normalized, so the traversal the recipe encodes reaches the target as written
        rather than being collapsed away. The recipe is grounded only on a CVE the finding itself
        names, so a file read recipe is never stapled onto a finding claiming a different, more
        severe CVE it cannot demonstrate, which the confirm judge would then rightly weaken."""
        if not self._recipes or finding.data.get("kind") != _KNOWN_VULN:
            return None
        host = urlsplit(finding.where).hostname or finding.where.split("/", 1)[0].split(":", 1)[0]
        node = next((n for n in world.nodes("domain") if n.payload.name == host), None)
        if node is None:
            return None
        scan = world.latest("cve_scanned", node.id)
        if scan is None or scan.payload.match != _VERSION_MATCH:
            return None
        primary = _primary_cve(finding)
        recipe = self._recipes.get(primary)
        if recipe is None or primary not in {c.id.upper() for c in scan.payload.cves}:
            return None
        http = world.latest("http", node.id)
        base = getattr(http.payload, "url", "") if http is not None else ""
        parts = urlsplit(base or f"https://{host}/")
        authority = parts.netloc or host
        url = f"{parts.scheme or 'https'}://{authority}{recipe.path}"
        expect = (f"the {recipe.cve} reproduction is confirmed when the live response "
                  f"satisfies: {recipe.expect}")
        return {"method": recipe.method, "url": url, "body": recipe.body, "expect": expect,
                "source": f"reproduction:{recipe.cve}"}

    def _chain_request(self, finding: Finding, world: World):
        """The multi-step exploit chain a known-vulnerability finding grounds on, as a poc_request
        describing its final step and the chain itself, or (None, None). Like the single recipe it
        fires only for a CVE the finding names and the lookup tied to the running version, and only
        at the exploit tier. The chain is driven whole by the exploit_chain capability, the
        poc_request's url is its final step, so confirm binds the receipt to it."""
        if not self._chains or finding.data.get("kind") != _KNOWN_VULN:
            return None, None
        host = urlsplit(finding.where).hostname or finding.where.split("/", 1)[0].split(":", 1)[0]
        node = next((n for n in world.nodes("domain") if n.payload.name == host), None)
        if node is None:
            return None, None
        scan = world.latest("cve_scanned", node.id)
        if scan is None or scan.payload.match != _VERSION_MATCH:
            return None, None
        primary = _primary_cve(finding)
        chain = self._chains.get(primary)
        if chain is None or primary not in {c.id.upper() for c in scan.payload.cves}:
            return None, None
        http = world.latest("http", node.id)
        base = getattr(http.payload, "url", "") if http is not None else ""
        parts = urlsplit(base or f"https://{host}/")
        authority = parts.netloc or host
        scheme = parts.scheme or "https"
        last = chain.steps[-1]
        path = re.sub(r"^https?://[^/]+", "",
                      last.path.replace("{{BaseURL}}", "").replace("{{RootURL}}", ""))
        if not path.startswith("/"):
            path = "/" + path
        request = {"method": last.method.upper(), "url": f"{scheme}://{authority}{path}",
                   "body": "", "expect": (f"the {chain.cve} reproduction is confirmed when the "
                                          f"live chain satisfies: {chain_summary(chain)}"),
                   "source": f"reproduction:{chain.cve}"}
        return request, chain

    def _observed_gets(self, world: World) -> dict:
        """Every GET the surface recorded, keyed by normalized url, so a finding's proof of
        concept can be matched to a request known to have been made. The sources are the host
        root probe, each probed endpoint, and each verified specification operation."""
        observed: dict = {}
        for node in world.nodes("domain"):
            http = world.latest("http", node.id)
            if http is not None and http.payload.status is not None:
                # the scheme the host actually answered on, so an http-only host is keyed as
                # http rather than a hardcoded https that a real observation never matched
                url = getattr(http.payload, "url", "") or f"https://{node.payload.name}/"
                observed[_norm_url(url)] = {"status": http.payload.status,
                                            "content_type": "", "source": f"http:{node.id}"}
        for node in world.nodes("endpoint"):
            endpoint = node.payload
            if endpoint.status is None:
                continue
            observed[_norm_url(endpoint.url)] = {
                "status": endpoint.status, "content_type": endpoint.content_type or "",
                "source": f"endpoint:{node.id}"}
        for fact in world.facts("spec_audit"):
            for operation in fact.payload.operations:
                if not operation.verified or operation.status is None:
                    continue
                url = urljoin(fact.payload.base, operation.path)
                observed[_norm_url(url)] = {
                    "status": operation.status, "content_type": operation.content_type or "",
                    "source": f"spec_audit:{fact.about}:{operation.path}"}
        return observed

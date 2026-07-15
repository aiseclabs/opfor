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
from dataclasses import replace
from urllib.parse import urljoin, urlsplit

from opfor.core import Finding, Node, World
from opfor.core.post_triage import PostTriage
from opfor.scenarios.attacksurface.reproduce import FindingClaim, PoCRequest

_URL_RE = re.compile(r"https?://[^\s;'\"`)>]+")


def _urls_in(text: str) -> list[str]:
    """The http urls a proof-of-concept string names, in order, so a finding's request can
    be matched to a recorded observation. Trailing punctuation the regex catches is trimmed."""
    return [m.rstrip(".,") for m in _URL_RE.findall(text or "")]


def _norm_url(url: str) -> str:
    """A url reduced to scheme, host, and path for matching, lowercased host, no query or
    fragment, and no trailing slash, so a proof of concept and an observation of the same
    request compare equal despite cosmetic differences."""
    parts = urlsplit(url.strip())
    host = parts.hostname or ""
    path = parts.path.rstrip("/")
    return f"{parts.scheme.lower()}://{host.lower()}{path}"


class FindingGrounder(PostTriage):
    """Ground each finding whose safe-read proof of concept names an observed GET, and no
    other, then materialize the grounded ones as world nodes for the reproduce phase."""

    def run(self, world: World, findings: tuple[Finding, ...]) -> list[Finding]:
        observed = self._observed_gets(world)
        out: list[Finding] = []
        for finding in findings:
            request = self._poc_request(finding, observed)
            if request is None:
                out.append(finding)
                continue
            grounded = replace(finding, data={**finding.data, "poc_request": request})
            # Only a grounded finding becomes a node, so the reproduce step never sees an
            # ungrounded claim. The node is materialized here, never inside triage.
            world.add(Node(id=grounded.id, type="finding", payload=FindingClaim(
                finding_id=grounded.id, title=grounded.title, severity=grounded.severity,
                where=grounded.where, request=PoCRequest(**request))))
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

    def _observed_gets(self, world: World) -> dict:
        """Every GET the surface recorded, keyed by normalized url, so a finding's proof of
        concept can be matched to a request known to have been made. The sources are the host
        root probe, each probed endpoint, and each verified specification operation."""
        observed: dict = {}
        for node in world.nodes("domain"):
            http = world.latest("http", node.id)
            if http is not None and http.payload.status is not None:
                url = f"https://{node.payload.name}/"
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

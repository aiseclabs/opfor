"""Post-triage grounding: rewrite each finding's proof of concept to the deterministic truth.

Triage judges the surface into findings and mutates nothing, and the model writes a proof of
concept as a hint. This step runs once after TRIAGE and does the one deterministic thing that is
not judgment. It derives an accurate, hand-runnable request for the finding, then overwrites the
finding's proof of concept with it, so the reported PoC is never a command the model invented.

A finding grounds strongest-first. The firmest ground is the one request the surface already
observed, a safe read, so the finding grounds on that recorded receipt and a request no capability
made is never dressed as an opfor-generated script. A known-vulnerability finding is a special case,
it is minted deterministically from the version match, see `cve`, so it already carries a
reference-anchored proof note this run did not write from a model, and the grounder leaves it
untouched rather than grounding or overwriting it.

This run never sends the request to the target, so a grounded PoC is written and labelled
unverified, an operator runs it by hand. A finding that grounds on nothing gets an honest note
saying no reproducible request could be grounded, never a fabricated command, invariant 5. The step
mints no finding and drops none, so the surface a run reports is unchanged in count, and it never
mutates a finding in place, a grounded finding is a new object.
"""

from __future__ import annotations

import json
import re
from dataclasses import replace
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit

from opfor.core import Finding, World
from opfor.core import Grounding

_URL_RE = re.compile(r"https?://[^\s;'\"`)>]+")
# The CVE ids a finding names, so a version match binds only to the finding that actually claims its
# CVE, never stapled onto a more severe finding about a different CVE it cannot demonstrate.
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# The label every grounded PoC carries, since this reconnaissance run writes the request but never
# sends it to the target, so a reader never mistakes a written PoC for one opfor executed.
_UNVERIFIED = "UNVERIFIED, not executed against the target by this reconnaissance run"


def _cited_cves(finding) -> set[str]:
    """The CVE ids a finding names across its title, evidence, and PoC, upper-cased."""
    text = " ".join((finding.title, finding.evidence, finding.poc))
    return {match.group(0).upper() for match in _CVE_RE.finditer(text)}


def _primary_cve(finding) -> str:
    """The CVE a finding is chiefly about, its title's first CVE, else its first cited one. Grounding
    binds to this, so a version match keys off the finding's own claim and a secondary CVE mentioned
    in the evidence cannot hijack the finding onto a different CVE, a file read stapled onto an RCE."""
    in_title = _CVE_RE.findall(finding.title)
    if in_title:
        return in_title[0].upper()
    cited = sorted(_cited_cves(finding))
    return cited[0] if cited else ""


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


# The evaluator and driver of a generated PoC, a fixed block appended below the per-finding data
# literals. A status matcher compares the response code, a word or regex matcher searches the chosen
# response part, and the matcher set combines by an `and` or `or` condition. It reads only the data
# literals above it, so the generator injects values and never code, and it sends nothing until an
# operator runs the file by hand.
_SCRIPT_DRIVER = '''
def _part_text(part, status, header_text, body):
    if part == "header":
        return header_text
    if part == "all":
        return header_text + "\\n" + body
    return body


def _matcher_hits(matcher, status, header_text, body):
    values = matcher.get("values") or []
    if not values:
        return False
    kind = matcher.get("type")
    if kind == "status":
        return any(str(status) == str(v) for v in values)
    hay = _part_text(matcher.get("part") or "body", status, header_text, body)
    if kind == "regex":
        hits = [re.search(v, hay) is not None for v in values]
    else:
        hits = [v in hay for v in values]
    return all(hits) if matcher.get("condition") == "and" else any(hits)


def confirmed(status, header_text, body):
    """PASS, FAIL, or None when there is no executable criterion, so a MANUAL case is honest."""
    if not MATCHERS:
        return None
    results = [_matcher_hits(m, status, header_text, body) for m in MATCHERS]
    return all(results) if MATCHERS_CONDITION == "and" else any(results)


def send(url):
    data = BODY.encode("utf-8") if BODY else None
    request = urllib.request.Request(url, method=METHOD, data=data)
    for name, value in HEADERS:
        request.add_header(name, value)
    try:
        response = urllib.request.urlopen(request, timeout=20)
        return response.status, dict(response.headers), response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read().decode("utf-8", "replace")


def main():
    hit = 1
    for url in CANDIDATE_URLS:
        try:
            status, headers, body = send(url)
        except Exception as exc:
            print("[ERROR] %s -> %s" % (url, exc))
            continue
        header_text = "\\n".join("%s: %s" % (name, value) for name, value in headers.items())
        verdict = confirmed(status, header_text, body)
        label = {True: "PASS", False: "FAIL", None: "MANUAL"}[verdict]
        print("[%s] %s -> HTTP %s" % (label, url, status))
        if verdict is None:
            print("no executable success criterion, check by hand against: " + EXPECT)
            print(body[:4000])
        elif verdict:
            print(body[:4000])
            hit = 0
    return hit


if __name__ == "__main__":
    sys.exit(main())
'''


def _poc_script(request: dict, finding: Finding) -> str:
    """A self-contained stdlib PoC script for a grounded finding. It encodes the method, every
    candidate url, the headers, the body, and the response matchers as data, then runs the fixed
    driver that decides PASS or FAIL exactly as the surface's own success check would. It uses only
    `urllib`, so it runs anywhere Python does with no dependency, and it is labelled unverified and
    never sent by this run, an operator runs it by hand against a system they are authorized to test."""
    method = (request.get("method") or "GET").upper()
    urls = request.get("urls") or [request.get("url", "")]
    headers = [list(pair) for pair in request.get("headers") or []]
    body = request.get("body") or ""
    matchers = request.get("matchers") or []
    condition = request.get("matchers_condition") or "or"
    expect = request.get("expect") or ""
    head = (
        '#!/usr/bin/env python3\n'
        '"""' + _UNVERIFIED + '.\n\n'
        'PoC for: ' + finding.title + '\n'
        'Where: ' + finding.where + '\n'
        'Expected: ' + expect + '\n'
        '\nThis script was written by an opfor reconnaissance run and was NOT sent to the target.\n'
        'It tries each candidate url in turn and prints PASS when the response satisfies the success\n'
        'criterion, FAIL when it does not, and MANUAL when the finding carries no executable check.\n'
        '"""\n'
        'import re\n'
        'import sys\n'
        'import urllib.error\n'
        'import urllib.request\n\n'
        'METHOD = ' + json.dumps(method) + '\n'
        'CANDIDATE_URLS = ' + json.dumps(urls, indent=4) + '\n'
        'HEADERS = ' + json.dumps(headers, indent=4) + '\n'
        'BODY = ' + json.dumps(body) + '\n'
        'MATCHERS = ' + json.dumps(matchers, indent=4) + '\n'
        'MATCHERS_CONDITION = ' + json.dumps(condition) + '\n'
        'EXPECT = ' + json.dumps(expect) + '\n')
    return head + _SCRIPT_DRIVER


def _grounded_poc(request: dict) -> str:
    """The proof-of-concept string for a grounded finding. It names the generated script an operator
    runs by hand and the marker that confirms the instance is affected, so the finding points at the
    runnable artifact rather than carrying a paraphrased command inline."""
    return (f"{_UNVERIFIED}. Run the generated PoC script `{request['script']}` by hand against a "
            f"target you are authorized to test. Expected: {request['expect']}")


def _script_name(finding: Finding, taken: set[str]) -> str:
    """A stable, unique file name for a finding's PoC script, `<cve-or-kind>-<host>.py`, so two
    findings on one host or one CVE across hosts never collide onto the same file."""
    cve = _primary_cve(finding)
    base = cve or str(finding.data.get("kind") or "poc")
    host = urlsplit(finding.where).hostname or finding.where
    slug = _URL_SLUG.sub("-", f"{base}-{host}".lower()).strip("-") or "poc"
    name = slug
    n = 2
    while name in taken:
        name = f"{slug}-{n}"
        n += 1
    taken.add(name)
    return f"{name}.py"


_URL_SLUG = re.compile(r"[^a-z0-9]+")


def _ungrounded_poc(finding: Finding) -> str:
    """The proof-of-concept string for a finding that grounds on nothing, an honest note and no
    fabricated command, invariant 5. A finding whose demonstration would take an attack says so,
    since this run does not exploit, and any other says no reproducible read could be grounded."""
    if "authorized exploitation" in (finding.poc or "").lower():
        return ("demonstrating this would require authorized exploitation, which this "
                "reconnaissance run does not perform, and no safe read could be grounded from the "
                "observed surface, so no reproducible PoC is asserted")
    return ("no reproducible request could be grounded from the observed surface, so no PoC is "
            "asserted for this finding")


class FindingGrounder(Grounding):
    """Rewrite each finding's proof of concept to a grounded, hand-runnable request, or an honest
    note when none grounds.

    A finding grounds strongest-first. The firmest ground is a request the surface already observed,
    a safe read, strict so a request no capability made is never dressed as an opfor-generated
    script. A known-vulnerability finding is minted deterministically from the version match and
    already carries its own reference-anchored note, so the grounder passes it through untouched. A
    finding that grounds on nothing gets an honest no-PoC note. Every PoC is labelled unverified,
    this run never sends it.
    """

    def run(self, world: World, findings: tuple[Finding, ...]) -> list[Finding]:
        observed = self._observed_gets(world)
        out: list[Finding] = []
        taken: set[str] = set()
        for finding in findings:
            # A known-vulnerability finding is minted deterministically from the version match, see
            # `cve`, and already carries a reference-anchored proof note this run did not write from a
            # model. The grounder grounds only model-written proofs, so it leaves that note untouched.
            if finding.data.get("kind") == "known-vulnerability":
                out.append(finding)
                continue
            # Tier 1: a request the surface already observed, a safe read, grounds a runnable script.
            request = self._poc_request(finding, observed)
            if request is not None:
                request = {**request, "script": f"poc/{_script_name(finding, taken)}"}
                script = _poc_script(request, finding)
                out.append(replace(finding, poc=_grounded_poc(request),
                                   data={**finding.data, "poc_request": request,
                                         "poc_script": script}))
                continue
            # Tier 2: nothing grounds it, an honest no-PoC note.
            out.append(replace(finding, poc=_ungrounded_poc(finding)))
        return out

    def _poc_request(self, finding: Finding, observed: dict) -> dict | None:
        """The reproducible GET a finding's safe-read proof of concept names, or None. The
        url is taken from the proof of concept itself, never from the finding's location, so
        the grounded PoC states exactly the request the finding claims rather than a
        different one that merely shares a host. The url must match a recorded observation,
        and an exploit proof of concept, one the model marked as needing authorization,
        is never grounded as a safe read."""
        poc = finding.poc or ""
        if not poc or "authorized exploitation" in poc.lower():
            return None
        for url in _urls_in(poc):
            receipt = observed.get(_norm_url(url))
            if receipt is not None:
                expect = f"HTTP {receipt['status']}"
                if receipt.get("content_type"):
                    expect += f" {receipt['content_type']}"
                # A safe read grounds on a single observed url. Its success criterion is that the
                # response status matches what was seen, so the generated script confirms rather than
                # leaving the reader to eyeball the reply.
                return {"method": "GET", "url": url.strip(), "urls": [url.strip()],
                        "headers": [], "body": "",
                        "matchers": [{"type": "status", "part": "body",
                                      "values": [str(receipt["status"])], "condition": "or"}],
                        "matchers_condition": "and", "expect": expect,
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

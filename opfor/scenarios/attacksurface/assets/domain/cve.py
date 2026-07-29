"""The known-vulnerability findings triage mints outside the model.

A version-matched CVE is a fact, not a verdict. The public database ties the identified running
version to an affected range, so the finding is minted deterministically here rather than judged by
the model, mirroring the completeness rules beside it. Its severity is the CVE's own CVSS base
severity. This pass does not weigh reachability, it reports the catalogued weakness the identified
version carries and says as much, so an operator reads the base severity and the exposure separately.

A product-name or keyword match is not tied to the running version, so its CVEs are reported once as
a single low, unconfirmed note rather than dropped or elevated, invariant 5. A host identified but
never CVE-scanned is a named blind spot, so a missing lookup never reads as a clean
no-known-vulnerabilities result.

This is the deliberate carve-out from invariant 2 for known vulnerabilities. A version match is a
database fact, so reporting it is deterministic and the model does not judge it. The surface-shape
classes stay model-judged, since whether an exposed shape is a real finding is a semantic call.
"""

from __future__ import annotations

from opfor.core import Finding, SEVERITIES, World

# The label every CVE note carries, since this reconnaissance run reports the catalogued weakness but
# never sends a request to the target, so a reader never mistakes a reported CVE for one confirmed
# against this instance.
_UNVERIFIED = "UNVERIFIED, not confirmed against this instance by this reconnaissance run"


def _severity(cve) -> str:
    """The reported severity for a version-matched CVE, its own base severity when the database gives
    a valid one, else derived from the CVSS base score, else INFO. A version match is a fact, so the
    severity is the catalogued one, not a reachability judgment this deterministic pass cannot make."""
    named = (cve.severity or "").strip().upper()
    if named in SEVERITIES:
        return named
    score = cve.cvss
    if score is None:
        return "INFO"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFO"


def _where(world: World, node) -> str:
    """The locator a host's CVE finding sits on, the url the host answered on when it is live, else a
    bare host name. Both fold onto the same subdomain in the report and the grounder."""
    http = world.latest("http", node.id)
    if http is not None and getattr(http.payload, "url", ""):
        return http.payload.url
    return f"https://{node.payload.name}/"


def _version_poc(product: str, version: str, cve) -> str:
    """The deterministic proof note for a version-matched CVE. It states the identified version, the
    matched CVE and its score, and points at the published references, since this run neither observed
    a safe read nor exploits, so the note rests on the catalogued advisory rather than a fabricated
    command. It is left untouched by the grounder, which grounds only model-written proofs."""
    refs = ", ".join(cve.references) if cve.references else "the public advisory for this CVE"
    return (f"{_UNVERIFIED}. The host runs {product} {version}, which the public database lists as "
            f"affected by {cve.id} (CVSS {cve.cvss} {cve.severity}). This run observed no safe read "
            f"demonstrating it and does not exploit, so consult the published references for "
            f"reproduction: {refs}")


def cve_findings(world: World) -> list[Finding]:
    """The known-vulnerability findings minted from the CVE scans, deterministically. A version match
    is reported per CVE at its base severity, a weaker product or keyword match as one low unconfirmed
    note, and an identified host with no scan as a named blind spot, so a missing lookup never reads
    as clean. It mints no finding for a host the scan found clean, an empty list is an honest negative.
    """
    out: list[Finding] = []
    for node in world.nodes("domain"):
        profile = world.latest("host_profile", node.id)
        identified = profile is not None and profile.payload.product
        scan = world.latest("cve_scan", node.id)
        if scan is None:
            if identified:
                out.append(_blindspot(node))
            continue
        payload = scan.payload
        if not payload.cves:
            continue
        where = _where(world, node)
        if payload.match == "version":
            out.extend(_version_findings(node, payload, where))
        else:
            out.append(_unconfirmed_finding(node, payload, where))
    return out


def _version_findings(node, payload, where: str) -> list[Finding]:
    """One finding per version-matched CVE, highest CVSS first, each graded at the CVE's own base
    severity and carrying the deterministic proof note. Distinct CVEs are distinct findings so each
    is tracked and graded on its own record, and the finding id carries the CVE id so two CVEs on one
    host do not collapse into one under the class-and-location dedup key."""
    ranked = sorted(payload.cves, key=lambda c: c.cvss if c.cvss is not None else -1.0, reverse=True)
    out: list[Finding] = []
    for cve in ranked:
        out.append(Finding(
            id=f"finding:known-vulnerability-{cve.id.lower()}:{node.payload.name}",
            title=f"{payload.product} {payload.version} is affected by {cve.id}",
            severity=_severity(cve),
            where=where,
            evidence=f"the host is identified as {payload.product} {payload.version}, and the public "
                     f"database ties {cve.id} (CVSS {cve.cvss} {cve.severity}) to that version's "
                     f"affected range. {cve.summary} Reported at the CVE base severity, this pass does "
                     f"not weigh whether the instance is reachable behind authentication",
            poc=_version_poc(payload.product, payload.version, cve),
            data={"kind": "known-vulnerability", "cve": cve.id, "cvss": cve.cvss,
                  "match": "version", "sources": ["cve_scan"]},
        ))
    return out


def _unconfirmed_finding(node, payload, where: str) -> Finding:
    """One low, unconfirmed note for a product or keyword match, whose CVEs are not tied to the
    running version. Reported rather than dropped, invariant 5, but not elevated, since the version is
    not established, so an operator confirms it falls in each affected range before acting."""
    ids = ", ".join(sorted({cve.id for cve in payload.cves}))
    basis = ("the product name across all versions, not the running version"
             if payload.match == "product" else "a product-name text match only")
    return Finding(
        id=f"finding:known-vulnerability-unconfirmed:{node.payload.name}",
        title=f"{payload.product} has {len(payload.cves)} candidate CVE(s), version not established",
        severity="LOW",
        where=where,
        evidence=f"the database matched these CVEs by {basis}, so they are not tied to the running "
                 f"version and may not apply. Confirm the exact version falls in each affected range "
                 f"before acting. Candidates: {ids}",
        poc=f"{_UNVERIFIED}. {payload.product} was matched by {basis}, so the running version is not "
            f"established. Confirm the version falls in each CVE's affected range before treating "
            f"these as applicable. Candidates: {ids}",
        data={"kind": "known-vulnerability", "match": payload.match, "sources": ["cve_scan"]},
    )


def _blindspot(node) -> Finding:
    """A named blind spot for a host identified as a product but never CVE-scanned, so a lookup that
    failed or a run suspended before it ran never reads as a clean no-known-vulnerabilities result,
    invariant 5. It is a fact about the reach of the run, so it stays in code beside the completeness
    rules."""
    return Finding(
        id=f"finding:blindspot:cve-lookup:{node.payload.name}",
        title=f"CVE lookup did not complete for {node.payload.name}",
        severity="INFO",
        where=node.payload.name,
        evidence="the host was identified as a product but its CVE lookup never completed, so its "
                 "known-vulnerability status is unknown rather than clean. Rerun to close the gap",
        data={"kind": "blindspot", "sources": ["host_profile"]},
    )

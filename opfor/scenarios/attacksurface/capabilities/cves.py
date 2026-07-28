"""ENRICH-phase CVE lookup capability, read a host's identity and query a public database."""

from __future__ import annotations

from opfor.core import Capability, Done, Fact, Outcome, Phase, Task, World
from opfor.scenarios.attacksurface.types import CVE, CVEScan
from opfor.scenarios.attacksurface.failures import _coverage_gap, net_failed


class CVELookup(Capability):
    """ENRICH: look up a live host's known vulnerabilities from its profiled identity.

    It reads the product, version, and CPE the profiling capability already derived from the
    host_profile fact, and the injected CVE seam looks that version up in a public database. It
    holds no model and no knowledge, it reads the identity fact, calls the seam, and records the
    raw result. Reading identity here rather than deriving it means a CVE-lookup failure never
    discards a successful identification, that fact already stands. An empty CVE list is a clean
    negative, a seam error is a loud Failed, and which CVE matters and how severe is triage's
    judgment. It queries public sources, never the target, so it is osint.
    """

    name = "cve_scan"
    phase = Phase.ENRICH
    osint = True

    def __init__(self, cve_fn) -> None:
        self._cve = cve_fn

    def run(self, task: Task, world: World) -> Outcome:
        profile = world.latest("host_profile", task.node)
        product = version = cpe = ""
        if profile is not None:
            product = profile.payload.product
            version = profile.payload.version
            cpe = profile.payload.cpe
        cves: tuple[CVE, ...] = ()
        match = ""
        available = 0
        if product:
            try:
                raw = self._cve(product, version, cpe)
            except Exception as exc:
                return net_failed("cve lookup", exc)
            # The match basis and the total count are one fact about the whole lookup, so the
            # scan reads them once off any record.
            match = str(raw[0].get("match", "")) if raw else ""
            available = int(raw[0].get("available", len(raw))) if raw else 0
            cves = tuple(
                CVE(id=str(c.get("id", "")), cvss=c.get("cvss"),
                    severity=str(c.get("severity", "")), summary=str(c.get("summary", "")),
                    references=tuple(str(u) for u in c.get("references", ())))
                for c in raw if c.get("id"))
        payload = CVEScan(product=product, version=version, cpe=cpe, match=match, cves=cves)
        facts = [Fact(kind="cve_scan", about=task.node, payload=payload)]
        if available > len(cves):
            # The database matched more CVEs than the bounded page returned, so the kept list is a
            # slice, not the whole set. Record the drop as a coverage gap so a partial lookup does
            # not read as the host's complete vulnerability picture, invariant 5.
            name = world.node(task.node).payload.name
            gap = _coverage_gap("cve_scan", name, len(cves), [
                f"NVD matched {available} CVEs for {product}, only {len(cves)} were retrieved, "
                f"the remaining {available - len(cves)} were not evaluated"])
            if gap is not None:
                facts.append(Fact(kind="coverage_gap", about=task.node, payload=gap))
        return Done(facts=tuple(facts))

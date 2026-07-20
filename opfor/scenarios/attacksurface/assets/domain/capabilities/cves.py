"""ENRICH-phase CVE lookup capability, read a host's identity and query a public database."""

from __future__ import annotations

from opfor.core import Capability, Done, Fact, Outcome, Phase, Task, World
from opfor.scenarios.attacksurface.assets.domain.types import CVE, CVEScan
from opfor.scenarios.attacksurface.assets.domain.capabilities.helpers import net_failed


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
        if product:
            try:
                raw = self._cve(product, version, cpe)
            except Exception as exc:
                return net_failed("cve lookup", exc)
            # The whole list is found on one basis per lookup, so the scan records it once.
            match = str(raw[0].get("match", "")) if raw else ""
            cves = tuple(
                CVE(id=str(c.get("id", "")), cvss=c.get("cvss"),
                    severity=str(c.get("severity", "")), summary=str(c.get("summary", "")),
                    references=tuple(str(u) for u in c.get("references", ())))
                for c in raw if c.get("id"))
        payload = CVEScan(product=product, version=version, cpe=cpe, match=match, cves=cves)
        return Done(facts=(Fact(kind="cve_scanned", about=task.node, payload=payload),))

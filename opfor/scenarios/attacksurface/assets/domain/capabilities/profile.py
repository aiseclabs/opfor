"""ENRICH-phase host profiling capability, the single place a host's identity is derived."""

from __future__ import annotations

from opfor.core import Capability, Done, Fact, Outcome, Phase, Task, World
from opfor.scenarios.attacksurface.assets.domain.classifiers import host_evidence
from opfor.scenarios.attacksurface.assets.domain.types import HostProfile
from opfor.scenarios.attacksurface.assets.domain.failures import _coverage_gap, net_failed


class ProfileHost(Capability):
    """ENRICH: derive what a live host is into one host_profile fact.

    It gathers the host's evidence and calls two injected seams, the composed identify seam
    for the product and the deterministic framework classifier, so this capability
    holds no model and no knowledge. It records one host_profile fact the CVE lookup and the
    report both read, so a host's identity is derived once, survives a later CVE-lookup failure,
    and exists even when no CVE seam is wired. Identifying nothing conclusively is a clean
    negative, a live host the seam judged it had too little evidence to identify records a
    coverage gap so the blind spot stays visible, a seam error is a loud Failed, and what the
    host's role is remains triage's judgment. It reads facts and public sources, never the
    target, so it is osint.
    """

    name = "domain_profile"
    phase = Phase.ENRICH
    osint = True

    def __init__(self, identify_fn, framework_fn, version_paths=()) -> None:
        self._identify = identify_fn
        self._frameworks = framework_fn
        self._version_paths = tuple(version_paths)

    def run(self, task: Task, world: World) -> Outcome:
        host = world.node(task.node)
        http = world.latest("http", task.node)
        http_payload = http.payload if http is not None else None
        product = version = cpe = ""
        conclusive = True
        if self._identify is not None:
            try:
                found = self._identify(host_evidence(world, host, self._version_paths))
            except Exception as exc:
                return net_failed("product identification", exc)
            product = str(found.get("product", "")).strip()
            version = str(found.get("version", "")).strip()
            cpe = str(found.get("cpe", "")).strip()
            conclusive = bool(found.get("conclusive", True))
        frameworks = tuple(self._frameworks(http_payload))
        payload = HostProfile(
            product=product, version=version, cpe=cpe, frameworks=frameworks)
        facts = [Fact(kind="host_profile", about=task.node, payload=payload)]
        if not product and not conclusive and http_payload is not None and http_payload.alive:
            # The identify seam judged the evidence too thin to decide, so an empty product on a
            # live host is unknown here, not a confirmed bespoke application. Record the gap so a
            # host the run reached but could not characterize stays a visible blind spot rather
            # than a silent clean negative, invariant 3 and 5. The seam makes the call, this
            # capability only records it. An unreachable host is the probe step's gap, not this one.
            name = host.payload.name
            gap = _coverage_gap("domain_profile", name, 1, [
                f"{name}: the host answered but exposed too little to identify, so its product "
                "is unknown rather than confirmed absent"])
            if gap is not None:
                facts.append(Fact(kind="coverage_gap", about=task.node, payload=gap))
        return Done(facts=tuple(facts))

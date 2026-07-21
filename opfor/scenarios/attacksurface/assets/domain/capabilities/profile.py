"""ENRICH-phase host profiling capability, the single place a host's identity is derived."""

from __future__ import annotations

from opfor.core import Capability, Done, Fact, Outcome, Phase, Task, World
from opfor.scenarios.attacksurface.assets.domain.profile import host_evidence
from opfor.scenarios.attacksurface.assets.domain.types import HostProfile
from opfor.scenarios.attacksurface.assets.domain.capabilities.failures import net_failed


class ProfileHost(Capability):
    """ENRICH: derive what a live host is into one host_profile fact.

    It gathers the host's evidence and calls three injected seams, the composed identify seam
    for the product, and the deterministic framework and edge classifiers, so this capability
    holds no model and no knowledge. It records one host_profile fact the CVE lookup and the
    report both read, so a host's identity is derived once, survives a later CVE-lookup failure,
    and exists even when no CVE seam is wired. Identifying nothing is a clean negative, a seam
    error is a loud Failed, and what the host's role is remains triage's judgment. It reads facts
    and public sources, never the target, so it is osint.
    """

    name = "domain_profile"
    phase = Phase.ENRICH
    osint = True

    def __init__(self, identify_fn, framework_fn, edge_fn) -> None:
        self._identify = identify_fn
        self._frameworks = framework_fn
        self._edge = edge_fn

    def run(self, task: Task, world: World) -> Outcome:
        host = world.node(task.node)
        name = host.payload.name
        resolved = world.latest("resolved", task.node)
        http = world.latest("http", task.node)
        resolved_payload = resolved.payload if resolved is not None else None
        http_payload = http.payload if http is not None else None
        product = version = cpe = ""
        if self._identify is not None:
            try:
                found = self._identify(host_evidence(world, host))
            except Exception as exc:
                return net_failed("product identification", exc)
            product = str(found.get("product", "")).strip()
            version = str(found.get("version", "")).strip()
            cpe = str(found.get("cpe", "")).strip()
        frameworks = tuple(self._frameworks(http_payload))
        front = self._edge(name, resolved_payload, http_payload)
        payload = HostProfile(
            product=product, version=version, cpe=cpe, frameworks=frameworks,
            edge=front[0] if front else "", edge_evidence=front[1] if front else "")
        return Done(facts=(Fact(kind="host_profile", about=task.node, payload=payload),))

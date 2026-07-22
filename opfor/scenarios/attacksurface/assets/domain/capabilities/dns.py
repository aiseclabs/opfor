"""ENRICH-phase DNS capabilities: resolution, and the email and DNS-integrity posture."""

from __future__ import annotations

from opfor.core import Capability, Done, Fact, Outcome, Phase, Task, World
from opfor.scenarios.attacksurface.assets.domain.failures import _coverage_gap, net_failed
from opfor.scenarios.attacksurface.assets.domain.types import DNSEmailPosture, Resolved


class ResolveDomain(Capability):
    """ENRICH: resolve a domain to its addresses, or mark it dangling."""

    name = "domain_resolve"
    phase = Phase.ENRICH
    osint = True  # a public DNS lookup of the target, a passive read

    def __init__(self, resolve_fn) -> None:
        self._resolve = resolve_fn

    def run(self, task: Task, world: World) -> Outcome:
        name = world.node(task.node).payload.name
        try:
            result = self._resolve(name)
        except Exception as exc:
            # A resolver outage is not a confirmed no-address, so it must not read as a clean
            # dangling host. It still records an errored `resolved` fact plus a coverage gap,
            # rather than a bare Failed that leaves no fact, so a run-level barrier waiting on
            # every domain being resolved is not wedged forever by one resolver failure while
            # the whole downstream branch is silently suppressed, invariant 3 and 5.
            payload = Resolved(resolvable=False, errored=True)
            facts = [Fact(kind="resolved", about=task.node, payload=payload)]
            gap = _coverage_gap("domain_resolve", name, 1, [
                f"{name}: resolver failed, {type(exc).__name__}: {exc}, so the name was neither "
                "resolved nor confirmed absent"])
            if gap is not None:
                facts.append(Fact(kind="coverage_gap", about=task.node, payload=gap))
            return Done(facts=tuple(facts))
        payload = Resolved(resolvable=result.resolvable,
                           addresses=result.addresses,
                           cnames=result.cnames)
        return Done(facts=(Fact(kind="resolved", about=task.node, payload=payload),))


class ProbeDNSEmailPosture(Capability):
    """ENRICH: read a registrable root's email-authentication and DNS-integrity posture.

    It reads public DNS only, SPF and DMARC TXT records, CAA records, and the resolver's
    DNSSEC validation flag, so it never touches the target and is osint. It reports the raw
    records, whether a missing SPF or a `p=none` DMARC rises to a finding is triage's
    judgment. It runs on roots, since email authentication is a property of the registrable
    domain, not of an arbitrary subdomain. A lookup that fails on every resolver is a loud
    Failed, never a silent clean absence, invariant 5.
    """

    name = "dns_email"
    phase = Phase.ENRICH
    osint = True

    def __init__(self, dns_fn) -> None:
        self._dns = dns_fn

    def run(self, task: Task, world: World) -> Outcome:
        name = world.node(task.node).payload.name
        try:
            posture = self._dns(name)
        except Exception as exc:
            return net_failed("dns email posture", exc)
        payload = DNSEmailPosture(
            domain=name,
            spf=posture.spf,
            dmarc=posture.dmarc,
            caa=posture.caa,
            dnssec=posture.dnssec,
        )
        return Done(facts=(Fact(kind="dns_email", about=task.node, payload=payload),))

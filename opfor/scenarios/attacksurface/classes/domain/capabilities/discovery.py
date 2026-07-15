"""MAP-phase discovery capabilities that grow the domain root and subdomain set."""

from __future__ import annotations

from opfor.core import Capability, Done, Fact, Failed, Node, Outcome, Phase, Task, World
from opfor.scenarios.attacksurface import config
from opfor.scenarios.attacksurface.net import registrable_root
from opfor.scenarios.attacksurface.classes.domain.types import CoverageGap, DomainData


class DiscoverDomains(Capability):
    """MAP: turn the org's hint domains into domain nodes, the roots of the domain class.

    Discovering domains from a bare name needs a paid reverse-lookup source, so this
    seeds from the operator's hints. A keyed source would slot in here later, the hints
    keep a run working with none.
    """

    name = "discover_domains"
    phase = Phase.MAP

    def run(self, task: Task, world: World) -> Outcome:
        org = world.node(task.node).payload
        # A host name is case-insensitive, so an operator hint is lowercased at the source,
        # keeping node ids canonical and same-host attribution from missing a mixed-case name.
        roots = tuple(
            Node(id=f"domain:{d.lower()}", type="domain",
                 payload=DomainData(name=d.lower(), root=d.lower(), source="hint",
                                    confidence="confirmed", evidence="operator hint"))
            for d in org.domains
        )
        # Inventory hosts enter as leaves under their registrable root, not as roots, so the
        # pivot and subdomain rules, gated on name == root, skip them, and only resolution
        # and probing enrich them. This is how a DNS export closes the wildcard blind spot.
        hosts = tuple(
            Node(id=f"domain:{h.lower()}", type="domain",
                 payload=DomainData(name=h.lower(), root=registrable_root(h), source="inventory",
                                    confidence="confirmed", evidence="operator inventory"))
            for h in org.hosts
        )
        return Done(facts=(Fact(kind="domains_discovered", about=task.node, yields=roots + hosts),))


class DomainPivot(Capability):
    """MAP: sibling root domains that share a certificate with a known root.

    A certificate names every host its holder proved control of, so a root bundled on
    the same certificate as a confirmed root is owned by the same party. This grows the
    set of roots from evidence, not from guessing a brand across every suffix, and since
    MAP loops to quiescence a newly found root pivots again, a snowball. It reads a
    public log, so it is osint.
    """

    name = "domain_pivot"
    phase = Phase.MAP

    def __init__(self, pivot_fn) -> None:
        self._pivot = pivot_fn

    def run(self, task: Task, world: World) -> Outcome:
        name = world.node(task.node).payload.name
        try:
            siblings = self._pivot(name)
        except Exception as exc:
            return Failed(reason=f"cert pivot {type(exc).__name__}: {exc}")
        # Cert co-tenancy is weaker evidence of ownership than a registration match, a shared
        # certificate can still bundle a few unrelated roots, so a cert-SAN sibling is recorded
        # as associated rather than confirmed, and triage sees the weaker confidence.
        found = tuple(
            Node(id=f"domain:{root}", type="domain",
                 payload=DomainData(name=root, root=root, source="cert-san",
                                    confidence="associated", evidence=evidence))
            for root, evidence in sorted(siblings.items())
        )
        return Done(facts=(Fact(kind="pivoted", about=task.node, yields=found),))


class DomainRegistrant(Capability):
    """MAP: sibling root domains that share a registrant with the org, via reverse-WHOIS.

    Ownership by registration is the definitional signal of who a domain belongs to, so a
    root whose registration record names the same registrant is owned by the same party.
    The search terms are a registrant identity tied to the org, an organization name or a
    known registrant email, handed in by the planner from `Org.whois_terms`, and the org
    name is the fallback term. It reads a public registration index through a keyed
    provider, so it is osint. Wired only when a key is set.
    """

    name = "domain_registrant"
    phase = Phase.MAP

    def __init__(self, reverse_fn) -> None:
        self._reverse = reverse_fn

    def run(self, task: Task, world: World) -> Outcome:
        org = world.node(task.node).payload
        terms = org.whois_terms or (org.name,)
        key = config.reverse_whois_key()
        roots: dict[str, str] = {}
        for term in terms:
            try:
                roots.update(self._reverse(term, key))
            except Exception as exc:
                return Failed(reason=f"reverse-whois {type(exc).__name__}: {exc}")
        found = tuple(
            Node(id=f"domain:{root}", type="domain",
                 payload=DomainData(name=root, root=root, source="reverse-whois",
                                    confidence="confirmed", evidence=evidence))
            for root, evidence in sorted(roots.items())
        )
        return Done(facts=(Fact(kind="registrant", about=task.node, yields=found),))


class Subdomains(Capability):
    """MAP: passively discovered subdomains of a root, as new domain nodes.

    The source is a union of public passive sources, certificate transparency and a
    passive-DNS provider, so a name here was seen in the wild without touching the target.
    """

    name = "domain_subdomains"
    phase = Phase.MAP

    def __init__(self, enumerate_fn) -> None:
        self._enumerate = enumerate_fn

    def run(self, task: Task, world: World) -> Outcome:
        root = world.node(task.node).payload.name
        try:
            names = self._enumerate(root)
        except Exception as exc:
            return Failed(reason=f"passive enumeration {type(exc).__name__}: {exc}")
        # A wildcard such as *.dev.example.com names its base but hides every host under it
        # from certificate transparency, so the base is recorded once and flagged, and the
        # flag is what triage reports as a blind spot rather than a silent gap.
        wildcard: dict[str, bool] = {}
        for name in names:
            base = name[2:] if name.startswith("*.") else name
            if base and base != root:
                wildcard[base] = wildcard.get(base, False) or name.startswith("*.")
        found = tuple(
            Node(id=f"domain:{base}", type="domain",
                 payload=DomainData(name=base, root=root, source="passive", wildcard=is_wild))
            for base, is_wild in sorted(wildcard.items())
        )
        facts = [Fact(kind="enumerated", about=task.node, yields=found)]
        # A source that stopped at its page cap left subdomains unfetched, so record the
        # gap for triage to report rather than let a bounded set read as the full surface.
        if getattr(names, "truncated", False):
            facts.append(Fact(kind="enumeration_truncated", about=task.node))
        # A source that errored while others answered is a blind spot, surfaced through the
        # same coverage-gap channel so a partial union does not read as the full surface.
        errors = getattr(names, "source_errors", ())
        if errors:
            facts.append(Fact(kind="coverage_gap", about=task.node, payload=CoverageGap(
                scan="domain_subdomains", host=root,
                attempted=getattr(names, "source_count", len(errors)),
                failed=len(errors), reasons=tuple(errors[:5]))))
        return Done(facts=tuple(facts))

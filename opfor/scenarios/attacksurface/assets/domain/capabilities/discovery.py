"""MAP-phase discovery capabilities that grow the domain root and subdomain set."""

from __future__ import annotations

from opfor.core import Capability, Done, Fact, Node, Outcome, Phase, Task, World
from opfor.scenarios.attacksurface import config
from opfor.scenarios.attacksurface.hostnames import looks_like_host, registrable_root
from opfor.scenarios.attacksurface.assets.domain.capabilities.helpers import _coverage_gap, net_failed
from opfor.scenarios.attacksurface.assets.domain.sources.roots import (
    root_from_redirect,
    roots_from_dmarc,
)
from opfor.scenarios.attacksurface.assets.domain.types import CoverageGap, DomainData


class DiscoverDomains(Capability):
    """MAP: turn the org's hint domains into domain nodes, the roots of the domain class.

    Discovering domains from a bare name needs a paid reverse-lookup source, so this
    seeds from the operator's hints. A keyed source would slot in here later, the hints
    keep a run working with none.
    """

    name = "discover_domains"
    phase = Phase.MAP
    osint = True

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


class DeclaredRoots(Capability):
    """MAP: grow roots outward via DMARC, a root the org owns declaring another root it owns.

    It starts from an owned root and reads that root's DMARC report address, so the owner is
    declaring the root, ladder rung 5, and a namesake cannot slip in. A declared root becomes an
    associated domain node and enters the pipeline. Third-party DMARC processors and shared hosts
    are dropped, so a processor is not mistaken for the org's own root. Reading a DMARC record is a
    public DNS lookup that never touches the target, so it is osint. The redirect self-declaration,
    which is an active HTTP request, is a separate scoped capability, `RedirectRoots`, so this
    passive reader stays osint and cannot probe an out-of-scope root.
    """

    name = "declared_roots"
    phase = Phase.MAP
    osint = True

    def __init__(self, dns_fn) -> None:
        self._dns = dns_fn

    def run(self, task: Task, world: World) -> Outcome:
        root = world.node(task.node).payload.root
        declared: dict[str, str] = {}
        errors: list[str] = []
        try:
            declared.update(roots_from_dmarc(str(self._dns(root).get("dmarc", "")), root))
        except Exception as exc:
            errors.append(f"dmarc {type(exc).__name__}")
        found = tuple(
            Node(id=f"domain:{name}", type="domain",
                 payload=DomainData(name=name, root=name, source="self-declared",
                                    confidence="associated", evidence=f"declared by {root}, {signal}"))
            for name, signal in sorted(declared.items())
        )
        facts: list[Fact] = [Fact(kind="declared", about=task.node, yields=found)]
        if errors:
            facts.append(Fact(kind="coverage_gap", about=task.node, payload=CoverageGap(
                scan="declared_roots", host=root, attempted=len(errors), failed=len(errors),
                reasons=tuple(errors))))
        return Done(facts=tuple(facts))


class RedirectRoots(Capability):
    """MAP: a root the org owns redirecting to another owned root, read from its redirect target.

    It follows an owned root's HTTP redirect, so a rebrand or a moved property that points the old
    root at a new one is the owner declaring the new root. A redirect within the anchor's own root
    or to a shared host declares nothing. Reading the redirect is an active HTTP request to the
    root, a scoped act rather than a public read, so unlike the DMARC declaration this is not osint
    and is authorized against scope, the redirect of a discovered out-of-scope sibling root is
    never probed.
    """

    name = "redirect_roots"
    phase = Phase.MAP
    osint = False

    def __init__(self, resolve_fn, probe_fn) -> None:
        self._resolve = resolve_fn
        self._probe = probe_fn

    def run(self, task: Task, world: World) -> Outcome:
        root = world.node(task.node).payload.root
        found: tuple[Node, ...] = ()
        errors: list[str] = []
        try:
            resolved = self._resolve(root)
            if resolved.get("resolvable"):
                location = str(self._probe(root, resolved.get("addresses", ())).get("location", ""))
                hit = root_from_redirect(location, root)
                if hit is not None:
                    found = (Node(id=f"domain:{hit[0]}", type="domain",
                                  payload=DomainData(name=hit[0], root=hit[0], source="self-declared",
                                                     confidence="associated",
                                                     evidence=f"declared by {root}, {hit[1]}")),)
        except Exception as exc:
            errors.append(f"redirect {type(exc).__name__}")
        facts: list[Fact] = [Fact(kind="redirect_declared", about=task.node, yields=found)]
        if errors:
            facts.append(Fact(kind="coverage_gap", about=task.node, payload=CoverageGap(
                scan="redirect_roots", host=root, attempted=1, failed=1, reasons=tuple(errors))))
        return Done(facts=tuple(facts))


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
    osint = True

    def __init__(self, pivot_fn) -> None:
        self._pivot = pivot_fn

    def run(self, task: Task, world: World) -> Outcome:
        name = world.node(task.node).payload.name
        try:
            siblings = self._pivot(name)
        except Exception as exc:
            return net_failed("cert pivot", exc)
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
    osint = True

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
                return net_failed("reverse-whois", exc)
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
    osint = True

    def __init__(self, enumerate_fn) -> None:
        self._enumerate = enumerate_fn

    def run(self, task: Task, world: World) -> Outcome:
        root = world.node(task.node).payload.name
        try:
            names = self._enumerate(root)
        except Exception as exc:
            return net_failed("passive enumeration", exc)
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


# An unlikely label that should not exist, resolved first so a wildcard zone, which answers
# every name, is detected before a permutation would read its blanket answer as real hosts.
_WILDCARD_PROBE = "opfor-wildcard-probe-6f3a9c2e"
_MAX_PERMUTATION_CANDIDATES = 256


def permutation_candidates(root: str, observed) -> list[str]:
    """Candidate subdomains built only from the labels and structures already observed under a
    root, so enumeration extends the seen surface rather than guessing from a generic
    dictionary. For each observed `label.suffix`, every observed leftmost label is tried at
    every observed suffix, and a name already observed is dropped. This is principled
    enumeration, a permutation of evidence, never a blind wordlist."""
    labels: set[str] = set()
    suffixes: set[str] = set()
    seen = set(observed)
    for name in seen:
        if name == root or not name.endswith("." + root):
            continue
        head, _, rest = name.partition(".")
        if head and rest:
            labels.add(head)
            suffixes.add(rest)
    candidates: set[str] = set()
    for suffix in suffixes:
        for label in labels:
            candidate = f"{label}.{suffix}"
            if candidate not in seen and looks_like_host(candidate):
                candidates.add(candidate)
    return sorted(candidates)


class PermuteSubdomains(Capability):
    """MAP: confirm subdomains permuted from observed labels, gated by a wildcard baseline.

    Passive discovery names the subdomains seen in the wild. This extends that set without
    guessing from a dictionary: it permutes the labels and structures already observed under a
    root and confirms each candidate by resolution. A wildcard zone answers every name, so
    resolution there proves nothing, so this first resolves an unlikely name and skips the
    whole permutation when that answers, recording a bare fact rather than a flood of false
    hosts. Resolving public DNS never touches the target, so it is osint.
    """

    name = "domain_permute"
    phase = Phase.MAP
    osint = True

    def __init__(self, resolve_fn) -> None:
        self._resolve = resolve_fn

    def run(self, task: Task, world: World) -> Outcome:
        root = world.node(task.node).payload.name
        observed = tuple(n.payload.name for n in world.nodes("domain")
                         if n.payload.root == root and n.payload.name != root)
        try:
            baseline = self._resolve(f"{_WILDCARD_PROBE}.{root}")
        except Exception as exc:
            return net_failed("wildcard baseline", exc)
        # a wildcard zone resolves every name, so a permutation cannot be confirmed here, the
        # blind spot is already surfaced by the enumeration wildcard flag, so just record the
        # fact and mint nothing rather than a flood of names that all resolve to the catch-all
        if baseline.get("resolvable"):
            return Done(facts=(Fact(kind="permuted", about=task.node),))
        candidates = permutation_candidates(root, observed)
        probed = candidates[:_MAX_PERMUTATION_CANDIDATES]
        found: list[Node] = []
        skipped: list[str] = []
        for candidate in probed:
            if world.node(f"domain:{candidate}") is not None:
                continue
            try:
                result = self._resolve(candidate)
            except Exception as exc:
                skipped.append(f"{candidate}: {type(exc).__name__}")
                continue
            if result.get("resolvable"):
                found.append(Node(
                    id=f"domain:{candidate}", type="domain",
                    payload=DomainData(name=candidate, root=root, source="permuted",
                                       confidence="confirmed",
                                       evidence="permuted from an observed label, resolves under "
                                                "an owned root with no wildcard")))
        if len(candidates) > len(probed):
            skipped.append(f"{len(candidates) - len(probed)} more candidates beyond the "
                           f"{_MAX_PERMUTATION_CANDIDATES} cap were not probed")
        facts = [Fact(kind="permuted", about=task.node, yields=tuple(found))]
        gap = _coverage_gap("domain_permute", root, len(probed), skipped)
        if gap is not None:
            facts.append(Fact(kind="coverage_gap", about=task.node, payload=gap))
        return Done(facts=tuple(facts))

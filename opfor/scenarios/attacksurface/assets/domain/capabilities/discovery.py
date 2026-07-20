"""MAP-phase discovery capabilities that grow the domain root and subdomain set."""

from __future__ import annotations

from opfor.core import Capability, Done, Fact, Failed, Node, Outcome, Phase, Task, World
from opfor.scenarios.attacksurface import config
from opfor.scenarios.attacksurface.hostnames import looks_like_host, registrable_root
from opfor.scenarios.attacksurface.assets.domain.capabilities.helpers import _coverage_gap
from opfor.scenarios.attacksurface.assets.domain.sources.roots import (
    root_from_redirect,
    roots_from_dmarc,
)
from opfor.scenarios.attacksurface.assets.domain.types import (
    CoverageGap,
    DomainData,
    ProposedRoots,
    RootCandidacy,
)


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


# A run does not confirm an unbounded proposal set, so the confirmer probes at most this many
# candidates, each a certificate lookup, and reports the rest as unconfirmed rather than
# silently dropping them.
_MAX_CANDIDATE_CONFIRMATIONS = 64


class DiscoverCandidateRoots(Capability):
    """MAP: propose candidate roots from the org name, the guess half of root discovery.

    A bare company name yields no root by evidence, so a union of free sources proposes candidates
    from the name. A candidate yields no domain node, so a guess never reaches the scanned surface
    until the confirmer proves ownership. A source that did not answer is reported as a coverage
    gap so a partial proposal is not read as complete, invariant 5. It reads public sources, osint.
    """

    name = "discover_candidate_roots"
    phase = Phase.MAP
    osint = True

    def __init__(self, candidate_fn) -> None:
        self._candidate = candidate_fn

    def run(self, task: Task, world: World) -> Outcome:
        org = world.node(task.node).payload
        try:
            result = self._candidate(org.name, org.whois_terms)
        except Exception as exc:
            gap = CoverageGap(scan="discover_candidate_roots", host=org.name, attempted=1,
                              failed=1, reasons=(f"proposal {type(exc).__name__}",))
            return Done(facts=(
                Fact(kind="root_candidates", about=task.node, payload=ProposedRoots()),
                Fact(kind="coverage_gap", about=task.node, payload=gap)))
        # A hint the operator already gave is a confirmed root, so it is never re-proposed as a
        # guess, keeping the candidate set to roots the run does not already know.
        known = {d.lower() for d in org.domains} | {registrable_root(h) for h in org.hosts}
        items = tuple(c for c in result.candidates if c.name not in known)
        facts = [Fact(kind="root_candidates", about=task.node, payload=ProposedRoots(items=items))]
        if result.failed:
            facts.append(Fact(kind="coverage_gap", about=task.node, payload=CoverageGap(
                scan="discover_candidate_roots", host=org.name, attempted=len(result.failed),
                failed=len(result.failed),
                reasons=tuple(f"proposal source {f}" for f in result.failed))))
        return Done(facts=tuple(facts))


class ConfirmRootCandidates(Capability):
    """MAP: promote a proposed root only when it shares a certificate with a root already owned.

    Every candidate is a name match, a namesake shares a prefix, so a name alone never confirms.
    Confirmation ties the candidate to a known root by certificate co-tenancy, ladder rung 2, the
    same evidence the cert-SAN pivot trusts. The known roots are the anchors, an operator hint or a
    pivot or registrant match. A confirmed candidate becomes a domain node and enters the pipeline,
    an unconfirmed one is reported and never scanned, so a guess never reaches the target,
    invariant 4. With no anchor, no candidate confirms, which is the honest result of a bare name
    the operator gave no known root for. It reads a public log, so it is osint.
    """

    name = "confirm_candidate_roots"
    phase = Phase.MAP
    osint = True

    def __init__(self, pivot_fn) -> None:
        self._pivot = pivot_fn

    def run(self, task: Task, world: World) -> Outcome:
        proposal = world.latest("root_candidates", task.node)
        candidates = proposal.payload.items if proposal is not None else ()
        anchors = {
            n.payload.name for n in world.nodes("domain")
            if n.payload.name == n.payload.root
            and n.payload.confidence in ("confirmed", "associated")
        }
        found: list[Node] = []
        confirmed: list[str] = []
        unconfirmed: list[str] = []
        cert_probes = 0
        for candidate in candidates:
            if candidate.name in anchors:
                continue  # already an owned root by another path, nothing to add
            if cert_probes >= _MAX_CANDIDATE_CONFIRMATIONS:
                unconfirmed.append(f"{candidate.name}: over the per-run confirmation cap")
                continue
            cert_probes += 1
            try:
                siblings = self._pivot(candidate.name)
            except Exception as exc:
                unconfirmed.append(f"{candidate.name}: pivot {type(exc).__name__}")
                continue
            anchor = next((r for r in sorted(siblings) if r in anchors), None)
            if anchor is None:
                unconfirmed.append(f"{candidate.name}: {candidate.signal}, "
                                   f"no shared certificate with an owned root")
                continue
            confirmed.append(candidate.name)
            found.append(Node(
                id=f"domain:{candidate.name}", type="domain",
                payload=DomainData(name=candidate.name, root=candidate.name, source=candidate.source,
                                   confidence="associated",
                                   evidence=f"proposed for the org, {candidate.signal}, "
                                            f"confirmed by a shared certificate with {anchor}")))
        report = RootCandidacy(proposed=len(candidates),
                               confirmed=tuple(confirmed), unconfirmed=tuple(unconfirmed))
        return Done(facts=(Fact(kind="root_candidates_confirmed", about=task.node,
                                payload=report, yields=tuple(found)),))


class DeclaredRoots(Capability):
    """MAP: grow roots outward, a root the org owns declaring another root it owns.

    Unlike the name proposers, this starts from an owned root and reads what that root itself
    names, its DMARC report address and its redirect target, so the owner is declaring the root,
    ladder rung 5, and a namesake cannot slip in. A declared root becomes an associated domain node
    and enters the pipeline. Third-party DMARC processors and shared hosts are dropped, so a
    processor or a link to a shared platform is not mistaken for the org's own root. It reads a
    public record, so it is osint.
    """

    name = "declared_roots"
    phase = Phase.MAP
    osint = True

    def __init__(self, dns_fn, resolve_fn, probe_fn) -> None:
        self._dns = dns_fn
        self._resolve = resolve_fn
        self._probe = probe_fn

    def run(self, task: Task, world: World) -> Outcome:
        root = world.node(task.node).payload.root
        declared: dict[str, str] = {}
        errors: list[str] = []
        try:
            declared.update(roots_from_dmarc(str(self._dns(root).get("dmarc", "")), root))
        except Exception as exc:
            errors.append(f"dmarc {type(exc).__name__}")
        try:
            resolved = self._resolve(root)
            if resolved.get("resolvable"):
                location = str(self._probe(root, resolved.get("addresses", ())).get("location", ""))
                hit = root_from_redirect(location, root)
                if hit is not None:
                    declared.setdefault(hit[0], hit[1])
        except Exception as exc:
            errors.append(f"redirect {type(exc).__name__}")
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
    osint = True

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
            return Failed(reason=f"wildcard baseline {type(exc).__name__}: {exc}")
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

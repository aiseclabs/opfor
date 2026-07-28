"""MAP-phase discovery capabilities that grow the domain root and subdomain set."""

from __future__ import annotations

from opfor.core import Capability, Done, Fact, Node, Outcome, Phase, Task, World
from opfor.scenarios.attacksurface.hostnames import looks_like_host, registrable_root
from opfor.scenarios.attacksurface.failures import _coverage_gap, net_failed
from opfor.scenarios.attacksurface.types import CoverageGap, DomainData


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
                 payload=DomainData(name=d.lower(), root=d.lower(), source="hint"))
            for d in org.domains
        )
        # Inventory hosts enter as leaves under their registrable root, not as roots, so the
        # subdomain and permute rules, gated on name == root, skip them, and only resolution
        # and probing enrich them. This is how a DNS export closes the wildcard blind spot.
        hosts = tuple(
            Node(id=f"domain:{h.lower()}", type="domain",
                 payload=DomainData(name=h.lower(), root=registrable_root(h), source="inventory"))
            for h in org.hosts
        )
        return Done(facts=(Fact(kind="domains_discovered", about=task.node, yields=roots + hosts),))


class EnumerateSubdomains(Capability):
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
    resolution there proves nothing. A wildcard can sit on a deeper zone, `*.dev.root` and not
    only `*.root`, so this probes an unlikely name in each distinct zone a candidate would live
    in and skips only the candidates under a zone that answers, confirming the rest, rather than
    trusting an apex probe alone. Resolving public DNS never touches the target, so it is osint.
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
        candidates = permutation_candidates(root, observed)
        probed = candidates[:_MAX_PERMUTATION_CANDIDATES]
        # Probe a wildcard baseline in every distinct zone a candidate would live in, not only the
        # apex, so a wildcard on a deeper zone is caught and its candidates are not confirmed off a
        # catch-all answer, which would invent a host without evidence, invariant 2 and 5.
        zones = sorted({candidate.partition(".")[2] for candidate in probed})
        wildcard_zones: set[str] = set()
        for zone in zones:
            try:
                baseline = self._resolve(f"{_WILDCARD_PROBE}.{zone}")
            except Exception as exc:
                return net_failed("wildcard baseline", exc)
            if baseline.resolvable:
                wildcard_zones.add(zone)
        found: list[Node] = []
        skipped: list[str] = []
        for candidate in probed:
            if candidate.partition(".")[2] in wildcard_zones:
                continue
            if world.node(f"domain:{candidate}") is not None:
                continue
            try:
                result = self._resolve(candidate)
            except Exception as exc:
                skipped.append(f"{candidate}: {type(exc).__name__}")
                continue
            if result.resolvable:
                found.append(Node(
                    id=f"domain:{candidate}", type="domain",
                    payload=DomainData(name=candidate, root=root, source="permuted")))
        if wildcard_zones:
            skipped.append(f"{len(wildcard_zones)} zone(s) answer every name as a wildcard, so "
                           f"their candidates were not confirmed: {', '.join(sorted(wildcard_zones))}")
        if len(candidates) > len(probed):
            skipped.append(f"{len(candidates) - len(probed)} more candidates beyond the "
                           f"{_MAX_PERMUTATION_CANDIDATES} cap were not probed")
        facts = [Fact(kind="permuted", about=task.node, yields=tuple(found))]
        gap = _coverage_gap("domain_permute", root, len(probed), skipped)
        if gap is not None:
            facts.append(Fact(kind="coverage_gap", about=task.node, payload=gap))
        return Done(facts=tuple(facts))

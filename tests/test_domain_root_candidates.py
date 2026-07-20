"""Bare-name root discovery: propose candidates from the org name, confirm by hard evidence.

The design is a guess-and-prove split. A free source proposes candidate roots from the company
name, and a candidate becomes a scanned root only when certificate co-tenancy proves the org
owns it, the same evidence the cert-SAN pivot trusts. A proposal that earns no proof is reported,
never scanned, so a guess never reaches the target.
"""

from __future__ import annotations

from opfor.core import Done, Fact, Node, Task, World
from opfor.scenarios.attacksurface.types import Org
from opfor.scenarios.attacksurface.assets.domain.capabilities.discovery import (
    ConfirmRootCandidates,
    DiscoverCandidateRoots,
)
from opfor.scenarios.attacksurface.assets.domain.sources.passive import roots_from_crtsh_org
from opfor.scenarios.attacksurface.assets.domain.types import (
    DomainData,
    ProposedRoots,
    RootCandidate,
)


def _org_world(**over):
    world = World()
    world.add(Node(id="org:ExampleCorp", type="org", payload=Org(name="ExampleCorp", **over)))
    return world


def test_crtsh_org_parse_folds_names_to_registrable_roots():
    rows = [
        {"name_value": "example.com\n*.example.com"},
        {"name_value": "api.example.net"},
        {"name_value": "not a host"},
    ]
    roots = roots_from_crtsh_org(rows, "ExampleCorp")
    assert set(roots) == {"example.com", "example.net"}
    assert "ExampleCorp" in roots["example.com"]


def test_proposal_records_candidates_and_drops_a_known_hint():
    # example.com is an operator hint, so it is a confirmed root, never re-proposed as a guess.
    world = _org_world(domains=("example.com",))

    def candidate_fn(name, terms):
        return {"example.com": "org match", "example-cdn.net": "org match"}

    outcome = DiscoverCandidateRoots(candidate_fn).run(
        Task(capability="discover_candidate_roots", node="org:ExampleCorp"), world)
    assert isinstance(outcome, Done)
    proposal = outcome.facts[0].payload
    assert isinstance(proposal, ProposedRoots)
    names = {c.name for c in proposal.items}
    assert names == {"example-cdn.net"}
    # a proposal yields no node, so a guess never enters the scanned surface
    assert outcome.facts[0].yields == ()


def test_unreachable_proposal_source_is_a_coverage_gap_not_a_failure():
    # crt.sh times out often, so a source failure is reported loud as a gap, not a run error, and
    # the empty proposal lets the confirmer no-op.
    world = _org_world()

    def candidate_fn(name, terms):
        raise TimeoutError("crt.sh timed out")

    outcome = DiscoverCandidateRoots(candidate_fn).run(
        Task(capability="discover_candidate_roots", node="org:ExampleCorp"), world)
    assert isinstance(outcome, Done)
    kinds = {f.kind for f in outcome.facts}
    assert "coverage_gap" in kinds and "root_candidates" in kinds
    gap = next(f.payload for f in outcome.facts if f.kind == "coverage_gap")
    assert "TimeoutError" in gap.reasons[0]
    proposal = next(f.payload for f in outcome.facts if f.kind == "root_candidates")
    assert proposal.items == ()


def _world_with_proposal(candidate_name):
    # An owned anchor root plus a proposal naming one candidate to confirm against it.
    world = _org_world()
    world.add(Node(id="domain:example.com", type="domain",
                   payload=DomainData(name="example.com", root="example.com",
                                      source="hint", confidence="confirmed")))
    world.absorb([Fact(kind="root_candidates", about="org:ExampleCorp",
                       payload=ProposedRoots(items=(
                           RootCandidate(name=candidate_name, source="crtsh-org",
                                         signal="a certificate subject organization matches 'ExampleCorp'"),)))])
    return world


def test_a_candidate_sharing_a_certificate_with_an_owned_root_is_confirmed():
    world = _world_with_proposal("example-cdn.net")

    def pivot_fn(domain):
        # the candidate is bundled on a certificate with the owned root, the ownership proof
        return {"example.com": "shares a certificate with example-cdn.net"}

    outcome = ConfirmRootCandidates(pivot_fn).run(
        Task(capability="confirm_candidate_roots", node="org:ExampleCorp"), world)
    assert isinstance(outcome, Done)
    node = next(n for f in outcome.facts for n in f.yields)
    assert node.id == "domain:example-cdn.net"
    assert node.payload.confidence == "associated"
    assert "example.com" in node.payload.evidence
    report = outcome.facts[0].payload
    assert report.confirmed == ("example-cdn.net",)
    assert report.unconfirmed == ()


def test_a_candidate_with_no_shared_certificate_is_reported_not_scanned():
    world = _world_with_proposal("example-evil.net")

    def pivot_fn(domain):
        return {}  # no certificate co-tenancy, so no ownership proof

    outcome = ConfirmRootCandidates(pivot_fn).run(
        Task(capability="confirm_candidate_roots", node="org:ExampleCorp"), world)
    assert isinstance(outcome, Done)
    # the guess yields no domain node, so it never reaches the target
    assert all(f.yields == () for f in outcome.facts)
    report = outcome.facts[0].payload
    assert report.confirmed == ()
    assert report.unconfirmed and "example-evil.net" in report.unconfirmed[0]

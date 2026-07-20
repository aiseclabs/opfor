"""Bare-name root discovery: propose from the org name, confirm by the candidate's ladder rung.

The design is a guess-and-prove split. A union of free sources proposes candidate roots from the
company name. A self-declared candidate, a root the org named on a verified account or a curated
entity, is confirmed by that declaration. A weak-tie candidate becomes a scanned root only when it
shares a certificate with an owned root. A proposal that earns no proof is reported, never scanned.
"""

from __future__ import annotations

from opfor.core import Done, Fact, Node, Task, World
from opfor.scenarios.attacksurface.types import Org
from opfor.scenarios.attacksurface.assets.domain.capabilities.discovery import (
    ConfirmRootCandidates,
    DiscoverCandidateRoots,
)
from opfor.scenarios.attacksurface.assets.domain.sources import roots as rootsrc
from opfor.scenarios.attacksurface.assets.domain.sources.passive import roots_from_crtsh_org
from opfor.scenarios.attacksurface.assets.domain.types import (
    DomainData,
    ProposalResult,
    ProposedRoots,
    RootCandidate,
)


def _org_world(**over):
    world = World()
    world.add(Node(id="org:ExampleCorp", type="org", payload=Org(name="ExampleCorp", **over)))
    return world


# --- sources: parse and compose ----------------------------------------------


def test_crtsh_org_parse_folds_names_to_registrable_roots():
    rows = [{"name_value": "example.com\n*.example.com"}, {"name_value": "api.example.net"},
            {"name_value": "not a host"}]
    roots = roots_from_crtsh_org(rows, "ExampleCorp")
    assert set(roots) == {"example.com", "example.net"}
    assert "ExampleCorp" in roots["example.com"]


def test_github_records_verified_in_the_signal_and_drops_shared_hosts():
    profiles = [
        {"login": "examplecorp", "blog": "https://example.com/", "email": "team@example.com",
         "verified": True},
        {"login": "namesake", "blog": "https://namesake.github.io", "email": "x@gmail.com",
         "verified": False},
    ]
    found = rootsrc.github_declared_roots("ExampleCorp", lambda n: profiles)
    by_name = {c.name: c for c in found}
    # a verified org is recorded in the signal, but it is still only a candidate, not confirmed
    assert "verified" in by_name["example.com"].signal
    # github.io and gmail.com are shared hosts, not the org's own root, so they are dropped
    assert "namesake.github.io" not in by_name and "gmail.com" not in by_name


def test_pypi_reads_project_url_domains_and_drops_shared_hosts(monkeypatch):
    monkeypatch.setattr(rootsrc, "_pypi_project", lambda slug: {
        "home_page": "https://example.com",
        "project_urls": {"Source": "https://github.com/example/x", "Docs": "https://docs.example.org"}})
    found = {c.name for c in rootsrc.pypi_org_roots("Example")}
    assert "example.com" in found and "example.org" in found
    assert "github.com" not in found  # a shared code host is not the org's own root


def test_propose_roots_unions_sources_first_wins_and_reports_a_failure():
    def gh():
        return [RootCandidate(name="example.com", source="github", signal="github blog")]

    def crt():
        # a duplicate from a later source does not replace the first source's signal
        return [RootCandidate(name="example.com", source="crtsh-org", signal="org match"),
                RootCandidate(name="example.net", source="crtsh-org", signal="org match")]

    def broken():
        raise TimeoutError("pypi timed out")

    result = rootsrc.propose_roots("ExampleCorp", (), sources=(
        ("github", gh), ("crtsh-org", crt), ("pypi", broken)))
    by_name = {c.name: c for c in result.candidates}
    assert by_name["example.com"].source == "github"  # first source wins the duplicate
    assert set(by_name) == {"example.com", "example.net"}
    assert result.failed and "pypi" in result.failed[0]


# --- capability: propose -----------------------------------------------------


def test_proposal_records_candidates_and_drops_a_known_hint():
    # example.com is an operator hint, so it is a confirmed root, never re-proposed as a guess.
    world = _org_world(domains=("example.com",))

    def candidate_fn(name, terms):
        return ProposalResult(candidates=(
            RootCandidate(name="example.com", source="github", signal="s"),
            RootCandidate(name="example-cdn.net", source="crtsh-org", signal="s")))

    outcome = DiscoverCandidateRoots(candidate_fn).run(
        Task(capability="discover_candidate_roots", node="org:ExampleCorp"), world)
    assert isinstance(outcome, Done)
    proposal = next(f.payload for f in outcome.facts if f.kind == "root_candidates")
    assert {c.name for c in proposal.items} == {"example-cdn.net"}
    # a proposal yields no node, so a guess never enters the scanned surface
    assert all(f.yields == () for f in outcome.facts)


def test_a_failed_source_is_reported_as_a_coverage_gap():
    world = _org_world()

    def candidate_fn(name, terms):
        return ProposalResult(candidates=(), failed=("crtsh-org TimeoutError",))

    outcome = DiscoverCandidateRoots(candidate_fn).run(
        Task(capability="discover_candidate_roots", node="org:ExampleCorp"), world)
    assert isinstance(outcome, Done)
    gap = next(f.payload for f in outcome.facts if f.kind == "coverage_gap")
    assert "crtsh-org" in gap.reasons[0]


# --- capability: confirm -----------------------------------------------------


def _world_with_proposal(*candidates):
    world = _org_world()
    world.add(Node(id="domain:example.com", type="domain",
                   payload=DomainData(name="example.com", root="example.com",
                                      source="hint", confidence="confirmed")))
    world.absorb([Fact(kind="root_candidates", about="org:ExampleCorp",
                       payload=ProposedRoots(items=tuple(candidates)))])
    return world


def test_a_name_matched_candidate_is_not_scanned_without_a_shared_certificate():
    # Even a GitHub-verified namesake is only a name match, so with no shared certificate it is
    # never scanned. This is the namesake guard: a French town hall or an unrelated maker space
    # that shares the name prefix must not enter the surface.
    world = _world_with_proposal(
        RootCandidate(name="namesake-makerspace.org", source="github",
                      signal="named on the GitHub org 'namesake', a GitHub-verified org"))

    def pivot_fn(domain):
        return {}  # the namesake shares no certificate with the owned root

    outcome = ConfirmRootCandidates(pivot_fn).run(
        Task(capability="confirm_candidate_roots", node="org:ExampleCorp"), world)
    assert all(f.yields == () for f in outcome.facts)
    report = outcome.facts[0].payload
    assert report.confirmed == () and "namesake-makerspace.org" in report.unconfirmed[0]


def test_a_weak_tie_sharing_a_certificate_with_an_owned_root_is_confirmed():
    world = _world_with_proposal(
        RootCandidate(name="example-cdn.net", source="crtsh-org", signal="org match"))

    def pivot_fn(domain):
        return {"example.com": "shares a certificate with example-cdn.net"}

    outcome = ConfirmRootCandidates(pivot_fn).run(
        Task(capability="confirm_candidate_roots", node="org:ExampleCorp"), world)
    node = next(n for f in outcome.facts for n in f.yields)
    assert node.id == "domain:example-cdn.net"
    assert "shared certificate with example.com" in node.payload.evidence


def test_a_weak_tie_with_no_shared_certificate_is_reported_not_scanned():
    world = _world_with_proposal(
        RootCandidate(name="example-evil.net", source="crtsh-org", signal="org match"))

    def pivot_fn(domain):
        return {}  # no certificate co-tenancy, so no ownership proof

    outcome = ConfirmRootCandidates(pivot_fn).run(
        Task(capability="confirm_candidate_roots", node="org:ExampleCorp"), world)
    assert all(f.yields == () for f in outcome.facts)  # the guess never becomes a scanned root
    report = outcome.facts[0].payload
    assert report.confirmed == () and report.unconfirmed and "example-evil.net" in report.unconfirmed[0]

from __future__ import annotations

from opfor.core import Budget, Node, Phase, Scope, World, run
from opfor.core.result import CLOSED

from tests.surface_fixtures import *


def test_run_closes():
    report = _run(_seed())
    assert report.closed
    assert report.status == CLOSED
    assert report.reached == Phase.TRIAGE

def test_expands_both_asset_classes_from_the_org():
    world = _seed()
    _run(world)
    assert {n.payload.name for n in world.nodes("domain")} >= {"www.example.com", "admin.example.com"}
    assert {n.payload.login for n in world.nodes("github_org")} == {"examplecorp"}
    assert len(world.nodes("github_repo")) == 2

def test_wildcard_certificate_is_reported_as_a_blind_spot():
    # *.dev.example.com hides its hosts from CT, the run must say so rather than look clean
    report = _run(_seed())
    blind = [f for f in report.findings if f.data.get("kind") == "blindspot"]
    assert len(blind) == 1
    assert blind[0].severity == "INFO"
    assert "dev.example.com" in blind[0].data["bases"]

def test_truncated_enumeration_is_reported_as_a_blind_spot():
    # a passive source that stopped at its page cap left subdomains unfetched, the run must
    # say so rather than present the bounded set as the complete surface
    from opfor.scenarios.attacksurface.assets.domain.sources import Enumeration

    def enum_truncated(root):
        found = Enumeration({"api.example.com"})
        found.truncated = True
        return found

    report, _scenario, _world = _run_capturing(enumerate_fn=enum_truncated)
    trunc = [f for f in report.findings if f.id == "finding:blindspot:enumeration"]
    assert len(trunc) == 1
    assert trunc[0].severity == "INFO"
    assert "example.com" in trunc[0].data["roots"]

def test_inventory_hosts_enter_the_surface_as_enriched_leaves():
    # a DNS-export host is resolved and triaged, but not re-enumerated, since it is a leaf
    world = _seed(hosts=("api.dev.example.com",))
    _run(world)
    node = world.node("domain:api.dev.example.com")
    assert node.payload.source == "inventory"
    assert node.payload.root == "example.com"
    assert world.has_fact(node.id, "resolved")
    assert not world.has_fact(node.id, "enumerated")

def test_wildcard_base_node_is_flagged():
    from opfor.core import Node, World
    from opfor.scenarios.attacksurface.assets.domain.capabilities import Subdomains
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData
    from opfor.scenarios.attacksurface.types import Org

    world = World()
    world.add(Node(id="org:x", type="org", payload=Org(name="X", domains=("example.com",))))
    world.add(Node(id="domain:example.com", type="domain",
                   payload=DomainData(name="example.com", root="example.com", source="hint")))
    cap = Subdomains(lambda root: {"*.dev.example.com", "api.example.com"})
    from opfor.core import Task
    outcome = cap.run(Task(capability="domain_subdomains", node="domain:example.com"), world)
    nodes = {n.payload.name: n.payload for n in outcome.facts[0].yields}
    assert nodes["dev.example.com"].wildcard is True
    assert nodes["api.example.com"].wildcard is False

def test_github_org_is_info_inventory():
    report = _run(_seed())
    gh = [f for f in report.findings if f.data["kind"] == "github_org"]
    assert gh and gh[0].where == "examplecorp"
    assert gh[0].severity == "INFO"
    assert gh[0].data["repos"] == 2

def test_github_attribution_keeps_the_owned_drops_the_namesake_flags_the_unproven():
    # three candidates match the name: one links to the in-scope root, one links to a
    # different root and is a namesake, one has no link and cannot be proven either way
    def search(name, token=""):
        return [
            {"login": "examplecorp", "url": "u", "org_id": 1, "name": "Example Corp",
             "blog": "https://example.com", "email": "", "verified": False},
            {"login": "example-lasers", "url": "u", "org_id": 2, "name": "Example Lasers",
             "blog": "https://example-lasers.io", "email": "", "verified": False},
            {"login": "examplish", "url": "u", "org_id": 3, "name": "Examplish",
             "blog": "", "email": "", "verified": False},
        ]

    report, _, world = _run_capturing(_seed(), search_fn=search)
    logins = {n.payload.login for n in world.nodes("github_org")}
    # the namesake proven to belong elsewhere is dropped, the other two are kept
    assert logins == {"examplecorp", "examplish"}
    attributed = {n.payload.login for n in world.nodes("github_org") if n.payload.attributed}
    assert attributed == {"examplecorp"}
    # the owned org is its own finding, the unproven one is collapsed into a caveat
    kinds = {f.data.get("kind") for f in report.findings}
    assert "github_org" in kinds and "github_unattributed" in kinds
    caveat = next(f for f in report.findings if f.data.get("kind") == "github_unattributed")
    assert caveat.data["logins"] == ["examplish"]

def test_class_restriction_runs_only_that_class():
    # github only: no domain nodes discovered, no domain findings
    world = _seed(classes=("github",))
    report = _run(world)
    assert report.closed
    assert world.nodes("domain") == ()
    assert world.nodes("github_org")
    assert all(f.data["kind"] == "github_org" for f in report.findings)

def test_total_resolution_failure_reports_incomplete_not_dangling():
    # when not one name resolves, the resolver is the problem, so the run must say
    # incomplete rather than call every name dangling
    def none_resolve(name):
        return {"resolvable": False, "addresses": ()}

    scenario = _make(resolve_fn=none_resolve)
    world = _seed(classes=("domain",))
    report = run(scenario, world, scope=Scope(max_tier="recon", hosts=(ROOT,)), budget=Budget(500))
    kinds = {f.data.get("kind") for f in report.findings}
    assert "incomplete" in kinds
    assert "dangling" not in kinds

def test_github_search_failure_still_closes():
    def boom(name, token=""):
        raise TimeoutError("github slow")

    scenario = _make(search_fn=boom)
    world = _seed()
    report = run(scenario, world, scope=Scope(max_tier="recon", hosts=(ROOT,)), budget=Budget(500))
    assert report.closed
    # the failure is loud in the report, not only in the ledger
    assert any("failed" in n and "discover_github" in n for n in report.notes)

def test_no_hint_domains_still_closes_via_github():
    # a bare name with no hint domains and the domain class off still closes on github
    world = _seed(domains=(), classes=("github",))
    report = _run(world)
    assert report.closed
    assert world.nodes("domain") == ()
    assert world.nodes("github_org")

def test_subdomain_enumeration_partial_failure_surfaces_a_coverage_gap():
    from opfor.core import Done, Task
    from opfor.scenarios.attacksurface.assets.domain.capabilities.discovery import Subdomains
    from opfor.scenarios.attacksurface.assets.domain.sources.passive import Enumeration
    from opfor.scenarios.attacksurface.assets.domain.types import DomainData

    world = World()
    world.add(Node(id="domain:example.com", type="domain",
                   payload=DomainData(name="example.com", root="example.com", source="seed")))

    def enumerate_fn(root):
        found = Enumeration({"a.example.com"})
        found.source_errors = ("virustotal: down",)
        found.source_count = 3
        return found

    outcome = Subdomains(enumerate_fn).run(
        Task(capability="domain_subdomains", node="domain:example.com"), world)
    assert isinstance(outcome, Done)
    # a source that failed while others answered is surfaced as a coverage gap, so the
    # partial subdomain set does not read as the full surface
    gaps = [f.payload for f in outcome.facts
            if f.kind == "coverage_gap" and f.payload.scan == "domain_subdomains"]
    assert gaps and gaps[0].failed == 1 and any("virustotal" in r for r in gaps[0].reasons)

def test_a_run_is_deterministic_across_repeats():
    # outcomes are absorbed in task-id order, not thread-completion order, so two identical
    # runs produce the same world and the same triage input
    a = _seed()
    _run(a)
    b = _seed()
    _run(b)
    assert [n.id for n in a.nodes()] == [n.id for n in b.nodes()]

def test_budget_cap_is_not_overshot_by_a_batch():
    from opfor.core import Budget, Scope, run
    world = _seed()
    budget = Budget(2)
    run(_make(), world, scope=Scope(max_tier="recon", hosts=(ROOT,)), budget=budget)
    # a batch is capped to the remaining budget, so the runaway ceiling is not blown past
    assert budget.steps <= 2

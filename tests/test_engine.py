"""The kernel: the mock scenario closes the loop, and the spine behaves."""

from __future__ import annotations

import pytest

from opfor.core import Budget, Node, Phase, Scope, World, run
from opfor.core.result import CLOSED, SUSPENDED
from opfor.scenarios.mock import MOCK


def _world_with_root() -> World:
    world = World()
    world.add(Node(id="root:1", type="root"))
    return world


def _run(world, *, budget=100, scope=None):
    return run(MOCK, world, scope=scope or Scope(max_tier="recon"), budget=Budget(budget))


def test_mock_closes_the_loop():
    world = _world_with_root()
    report = _run(world)
    assert report.closed
    assert report.status == CLOSED
    assert report.reached == Phase.TRIAGE
    assert report.terminal == Phase.TRIAGE


def test_map_grew_the_world():
    world = _world_with_root()
    _run(world)
    assert len(world.nodes("widget")) == 3


def test_triage_mints_findings_only_for_interesting():
    world = _world_with_root()
    report = _run(world)
    # widget:0 has value 0 and is not interesting, widget:1 and widget:2 are
    assert len(report.findings) == 2
    assert {f.where for f in report.findings} == {"widget:1", "widget:2"}
    assert all(f.severity == "MEDIUM" for f in report.findings)


def test_budget_exhaustion_suspends_not_closes():
    world = _world_with_root()
    # one step is not enough to run discover, inspect x3, so the run must suspend
    report = run(MOCK, world, scope=Scope(max_tier="recon"), budget=Budget(1))
    assert report.status == SUSPENDED
    assert not report.closed
    assert any("budget" in n for n in report.notes)


def test_no_reemit_is_idempotent():
    world = _world_with_root()
    r1 = _run(world)
    # a second run over the already-enriched world still closes and re-judges
    r2 = _run(world)
    assert r1.closed and r2.closed
    assert len(world.nodes("widget")) == 3
    assert len(r2.findings) == 2


def test_phase_upto_is_ordered_and_inclusive():
    assert Phase.upto(Phase.ENRICH) == (Phase.SEED, Phase.MAP, Phase.ENRICH)
    assert Phase.upto(Phase.TRIAGE)[-1] == Phase.TRIAGE


def test_scope_denies_out_of_scope_host():
    scope = Scope(max_tier="recon", hosts=("example.com",))
    d = scope.authorize("recon", osint=False, host="evil.test")
    assert not d.allowed
    d2 = scope.authorize("recon", osint=False, host="api.example.com")
    assert d2.allowed


def test_scope_waves_through_passive_osint():
    scope = Scope(max_tier="recon")
    d = scope.authorize("recon", osint=True)
    assert d.allowed


def test_scope_intrusive_needs_authorization():
    scope = Scope(max_tier="intrusive", hosts=("example.com",), authorized=False)
    d = scope.authorize("intrusive", osint=False, host="example.com")
    assert not d.allowed


def test_unknown_scenario_fails_loud():
    from opfor.scenarios.registry import get_scenario
    with pytest.raises(KeyError):
        get_scenario("nope")

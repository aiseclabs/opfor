"""The kernel: the mock scenario closes the loop, and the spine behaves."""

from __future__ import annotations

from pathlib import Path

import pytest

from opfor.core import (Budget, Capability, Fact, Later, Node, Phase, RuleSet, Scenario, Scope,
                        Task, Triage, World, resume, run)
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


# --- async suspend and resume ----------------------------------------------------------


class _AsyncProbe(Capability):
    """MAP: dispatches work whose result arrives later, so the run suspends until resume."""

    name = "async_probe"
    phase = Phase.MAP
    osint = True

    def run(self, task, world):
        return Later(handle="h1", note="awaiting external callback")


class _NoTriage(Triage):
    def judge(self, world):
        return []


def _async_scenario() -> Scenario:
    """A minimal scenario whose one capability parks an async task, so the loop suspends and
    can only close once the parked result is fed back through resume."""
    def probe_rule(world: World) -> list[Task]:
        # emit the probe once, and stop once the async callback fact has arrived
        if world.has_fact("root:1", "callback"):
            return []
        return [Task(capability="async_probe", node="root:1")]

    return Scenario(
        name="async-mock",
        content_root=Path(__file__).resolve().parent,
        capabilities=(_AsyncProbe(),),
        planner=RuleSet({Phase.MAP: [probe_rule]}),
        triage=_NoTriage(),
        terminal=Phase.TRIAGE,
    )


def test_async_work_suspends_with_a_named_pending_handle_and_resumable_state():
    world = World()
    world.add(Node(id="root:1", type="root"))
    report = run(_async_scenario(), world, scope=Scope(max_tier="recon"), budget=Budget(100))
    # the run stopped on async work, and says so rather than reading as a clean close
    assert report.status == SUSPENDED
    assert not report.closed
    assert report.pending == ("h1",)
    assert any("async" in n for n in report.notes)
    # the resumable state rides the report, so the parked run is not lost
    assert report.state is not None


def test_resume_feeds_the_async_result_back_and_closes_the_run():
    world = World()
    world.add(Node(id="root:1", type="root"))
    report = run(_async_scenario(), world, scope=Scope(max_tier="recon"), budget=Budget(100))
    assert report.status == SUSPENDED

    # the async result arrives later and is fed back through its handle, unblocking the run
    closed = resume(report.state, {"h1": (Fact(kind="callback", about="root:1"),)})
    assert closed.closed
    assert closed.status == CLOSED
    assert closed.reached == Phase.TRIAGE
    assert world.has_fact("root:1", "callback")


def test_resume_with_an_unknown_handle_is_loud_not_silent():
    world = World()
    world.add(Node(id="root:1", type="root"))
    report = run(_async_scenario(), world, scope=Scope(max_tier="recon"), budget=Budget(100))
    # a result for a handle no task is parked under is recorded, never silently dropped, and
    # the still-pending real handle keeps the run suspended
    again = resume(report.state, {"ghost": (Fact(kind="callback", about="root:1"),)})
    assert again.status == SUSPENDED
    assert any("ghost" in n for n in again.notes)
    assert again.pending == ("h1",)

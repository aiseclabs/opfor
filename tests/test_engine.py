"""The kernel: the mock scenario closes the loop, and the spine behaves."""

from __future__ import annotations

from pathlib import Path

import pytest

from opfor.core import (Budget, Capability, Fact, Later, Node, Phase, RuleSet, Scenario, Scope,
                        Task, Triage, World, resume, run)
from opfor.core.result import CLOSED, ERRORED, SUSPENDED
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


# --- budget suspension resumes, and error suspension says why --------------------------


def test_triage_charges_the_budget_for_the_model_judge():
    """The TRIAGE judge is a model call, the run's most expensive step, so the runaway cap
    counts it. MOCK charges MAP discover (1) + ENRICH inspect x3 (3) + the TRIAGE judge (1)."""
    world = _world_with_root()
    budget = Budget(100)
    report = run(MOCK, world, scope=Scope(max_tier="recon"), budget=budget)
    assert report.reached == Phase.TRIAGE
    assert budget.steps == 5


def test_a_budget_suspension_carries_resumable_state_and_continues_when_topped_up():
    """A run stopped purely by budget is resumable: it carries its state and the phase it
    stopped in, so raising the ceiling and resuming continues from there rather than losing
    the run or restarting at SEED."""
    world = _world_with_root()
    report = run(MOCK, world, scope=Scope(max_tier="recon"), budget=Budget(1))
    assert report.status == SUSPENDED
    assert report.state is not None
    assert report.state.resume_from == Phase.MAP
    # the operator raises the ceiling and resumes, the run picks up and closes
    report.state.budget.max_steps = 100
    closed = resume(report.state, {})
    assert closed.closed
    assert closed.reached == Phase.TRIAGE
    assert len(world.nodes("widget")) == 3


def test_budget_running_out_on_parked_async_keeps_the_resume_point_and_names_the_wait():
    """The budget cut-off must not mask parked async work. A run that spends its last step
    parking an async task suspends naming both the budget and the pending handle, records the
    phase to resume from, and still closes once the ceiling is raised and the result arrives."""
    world = World()
    world.add(Node(id="root:1", type="root"))
    report = run(_async_scenario(), world, scope=Scope(max_tier="recon"), budget=Budget(1))
    assert report.status == SUSPENDED
    assert report.pending == ("h1",)
    assert any("budget" in n for n in report.notes)
    assert any("async" in n for n in report.notes)
    assert report.state.resume_from == Phase.MAP
    # top up and deliver the async result, the run resumes in MAP and closes
    report.state.budget.max_steps = 100
    closed = resume(report.state, {"h1": (Fact(kind="callback", about="root:1"),)})
    assert closed.closed
    assert world.has_fact("root:1", "callback")


class _BoomTriage(Triage):
    def judge(self, world):
        raise RuntimeError("judge blew up")


def test_an_orchestration_error_reports_errored_not_a_resumable_suspend():
    """A triage, planner, or confirm that raises must still leave the run answering with a
    Report, never an exception escaping the engine. The status is ERRORED, not SUSPENDED, and
    the run carries no resumable state, so a deterministic code crash is not mistaken for a
    stall to retry or top up."""
    world = _world_with_root()
    scenario = Scenario(
        name="boom-triage",
        content_root=Path(__file__).resolve().parent,
        capabilities=(),
        planner=RuleSet({}),
        triage=_BoomTriage(),
        terminal=Phase.TRIAGE,
    )
    report = run(scenario, world, scope=Scope(max_tier="recon"), budget=Budget(100))
    assert report.status == ERRORED
    assert not report.closed
    assert report.state is None
    assert any("RuntimeError" in n and "TRIAGE" in n for n in report.notes)

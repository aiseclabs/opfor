"""G1: a run persists its state to disk as it advances, so a crash resumes rather than restarts.

A closed run needs no resume, so its checkpoint is removed. A run stopped short keeps its
checkpoint, and a fresh process rebuilds it from JSON alone and drives it to closure, the
crash-recovery path the in-memory state cannot serve.
"""

from __future__ import annotations

from opfor.core import Budget, Checkpoint, Node, Scope, World, restore, resume_run, run
from opfor.core.result import CLOSED, SUSPENDED
from opfor.scenarios.mock import MOCK


def _world():
    world = World()
    world.add(Node(id="root:1", type="root"))
    return world


def test_a_closed_run_removes_its_checkpoint(tmp_path):
    ckpt = tmp_path / "checkpoint.json"
    report = run(MOCK, _world(), scope=Scope(max_tier="recon"), budget=Budget(100),
                 checkpoint_path=ckpt)
    assert report.closed
    assert not ckpt.exists()  # a closed run needs no resume, so its checkpoint is cleaned up


def test_a_run_without_a_path_still_works():
    report = run(MOCK, _world(), scope=Scope(max_tier="recon"), budget=Budget(100))
    assert report.closed  # checkpointing is opt-in, an unset path is a plain in-memory run


def test_a_suspended_run_keeps_a_checkpoint_that_restores_and_closes(tmp_path):
    ckpt = tmp_path / "checkpoint.json"
    report = run(MOCK, _world(), scope=Scope(max_tier="recon"), budget=Budget(1),
                 checkpoint_path=ckpt)
    assert report.status == SUSPENDED
    assert ckpt.exists()  # a run stopped short leaves a resumable checkpoint on disk

    # a fresh process rebuilds the run from the file alone, tops up the budget, and closes it
    state = restore(Checkpoint.from_json(ckpt.read_text(encoding="utf-8")), MOCK)
    state.checkpoint_path = ckpt
    state.budget.max_steps = 100
    closed = resume_run(state)
    assert closed.closed and closed.status == CLOSED
    assert not ckpt.exists()  # the resumed run closed, so it removed the checkpoint

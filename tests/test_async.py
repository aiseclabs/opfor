"""Async late-delivery: invariant 3's suspend / deliver / resume path.

A capability whose result arrives later (the phishing "hours later" case) returns
a pending observation with a handle. The shell must park it, report the run
suspended rather than done, survive a checkpoint, accept the late result through
deliver() in what may be a fresh process, and then resume to drain the work the
result unlocked.
"""

from __future__ import annotations

import pytest

from opfor.agent.planner import FunctionPlanner
from opfor.engine.budget import Budget
from opfor.engine.control import ControlShell
from opfor.engine.graph import SituationGraph
from opfor.engine.scope import Scope
from opfor.engine.state import Workspace
from opfor.engine.tasks import Task
from opfor.model import Artifact, Fact, Observation, Target
from opfor.plugins.base import Executor


class PhishExecutor(Executor):
    """Dispatches a phishing email; the click arrives later, out of band."""

    capability = "phish"

    def run(self, task, graph) -> Observation:
        # The deed is dispatched, not finished: pending, with a handle to track it.
        return Observation(
            entrypoint_id=task.id, action="phish", raw={}, pending=True, handle=f"h:{task.id}"
        )

    def perceive(self, obs) -> list[Fact]:
        if obs.raw.get("clicked"):
            cred = Artifact(id=f"creds:{obs.entrypoint_id}", kind="captured_creds")
            return [Fact(kind="phish-success", about=obs.entrypoint_id, yields=(cred,))]
        return [Fact(kind="phish-ignored", about=obs.entrypoint_id)]


def _rule(graph):
    return [
        Task(id=f"phish:{t.id}", capability="phish", target=t.id, scope_host=t.props["host"])
        for t in graph.targets()
        if t.kind == "person"
    ]


def _shell(tmp_path):
    return ControlShell(
        executors={"phish": PhishExecutor()},
        planner=FunctionPlanner(_rule),
        scope=Scope(hosts=("lab",), max_tier="recon"),
        workspace=Workspace(tmp_path / "run"),
        budget=Budget(50),
    )


def test_run_suspends_awaiting_async_then_delivers_and_resumes(tmp_path):
    graph = SituationGraph()
    graph.add_target(Target(id="alice", kind="person", props={"host": "lab"}))

    # 1. The dispatch parks the task: the run is suspended, not done.
    result = _shell(tmp_path).run(graph)
    assert result.done is False
    assert result.stopped_reason == "awaiting async results"
    assert result.tasks["waiting"] == 1
    assert not result.graph.entities("artifact")  # nothing captured yet

    # 2. Hours later, in a fresh shell on the same workspace, the click arrives.
    new = _shell(tmp_path).deliver("h:phish:alice", {"clicked": True})
    assert new == 1  # the captured-creds artifact

    # 3. Resuming drains the run: the artifact is on the graph and we are done.
    final = _shell(tmp_path).resume()
    assert final.done is True
    assert final.stopped_reason == "no ready tasks"
    assert len(final.graph.entities("artifact")) == 1


def test_deliver_unknown_handle_fails_loud(tmp_path):
    graph = SituationGraph()
    graph.add_target(Target(id="bob", kind="person", props={"host": "lab"}))
    shell = _shell(tmp_path)
    shell.run(graph)

    with pytest.raises(KeyError):
        shell.deliver("h:does-not-exist", {"clicked": True})
    assert any(e["kind"] == "deliver_unknown" for e in shell.ledger.entries())


def test_pending_without_handle_is_surfaced_not_awaited(tmp_path):
    # A pending observation with no handle cannot be tracked; the shell must
    # surface it (ledger) and not park forever.
    class NoHandleExecutor(Executor):
        capability = "phish"

        def run(self, task, graph):
            return Observation(entrypoint_id=task.id, action="phish", raw={}, pending=True)

        def perceive(self, obs):
            return []

    graph = SituationGraph()
    graph.add_target(Target(id="carol", kind="person", props={"host": "lab"}))
    shell = ControlShell(
        executors={"phish": NoHandleExecutor()},
        planner=FunctionPlanner(_rule),
        scope=Scope(hosts=("lab",), max_tier="recon"),
        workspace=Workspace(tmp_path / "run"),
        budget=Budget(50),
    )
    result = shell.run(graph)
    assert result.done is True  # not stuck waiting
    assert any(e["kind"] == "await_no_handle" for e in shell.ledger.entries())

"""The human-in-the-loop seam: an optional approval gate after authorization."""

from opfor.engine.budget import Budget
from opfor.engine.control import ControlShell
from opfor.engine.graph import SituationGraph
from opfor.engine.scope import Scope
from opfor.engine.state import Workspace
from opfor.engine.tasks import Task
from opfor.model import Fact, Observation
from opfor.plugins.base import Executor


class _Counter(Executor):
    capability = "noop"

    def __init__(self):
        self.ran = []

    def run(self, task, graph):
        self.ran.append(task.id)
        return Observation(entrypoint_id=task.id, action="noop", raw={})

    def perceive(self, observation):
        return [Fact(kind="done", about=observation.entrypoint_id)]


class _Planner:
    def __init__(self, tasks):
        self._tasks = tasks

    def expand(self, graph):
        return list(self._tasks)


def _tasks():
    return [
        Task(id="probe", capability="noop", target="h", tier="probe", scope_host="h"),
        Task(id="intrusive", capability="noop", target="h", tier="intrusive", scope_host="h"),
    ]


def test_default_is_push_button_no_approval_needed(tmp_path):
    ex = _Counter()
    shell = ControlShell(
        executors={"noop": ex}, planner=_Planner(_tasks()),
        scope=Scope(hosts=("h",), max_tier="intrusive", authorized=True),
        workspace=Workspace(tmp_path), budget=Budget(50),  # approve=None
    )
    shell.run(SituationGraph())
    assert set(ex.ran) == {"probe", "intrusive"}  # auto-approved


def test_approval_hook_can_gate_a_task(tmp_path):
    ex = _Counter()
    # An approver that declines anything intrusive.
    shell = ControlShell(
        executors={"noop": ex}, planner=_Planner(_tasks()),
        scope=Scope(hosts=("h",), max_tier="intrusive", authorized=True),
        workspace=Workspace(tmp_path), budget=Budget(50),
        approve=lambda task, decision: task.tier != "intrusive",
    )
    shell.run(SituationGraph())
    assert ex.ran == ["probe"]  # the intrusive task was declined at the seam

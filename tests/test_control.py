import threading

from opfor.agent.planner import FunctionPlanner
from opfor.engine.budget import Budget
from opfor.engine.control import ControlShell
from opfor.engine.graph import SituationGraph
from opfor.engine.scope import Scope
from opfor.engine.state import Workspace
from opfor.engine.tasks import Task
from opfor.model import Artifact, Credential, Fact, Observation, Target
from opfor.plugins.base import Executor


class MockExecutor(Executor):
    """Reads a page. Reading / leaks a credential; reading /admin yields loot."""

    capability = "mock_read"

    def run(self, task, graph):
        return Observation(
            entrypoint_id=task.id,
            action="mock_read",
            raw={"ref": task.params["ref"], "target": task.target},
        )

    def perceive(self, obs):
        ref, target = obs.raw["ref"], obs.raw["target"]
        if ref == "/":
            cred = Credential(id=f"cred:{target}", kind="session", unlocks=(target,))
            return [Fact(kind="cred", about=obs.entrypoint_id, yields=(cred,))]
        if ref == "/admin":
            loot = Artifact(id=f"loot:{target}", kind="loot")
            return [Fact(kind="loot", about=obs.entrypoint_id, yields=(loot,))]
        return [Fact(kind="seen", about=obs.entrypoint_id)]


def _mock_rule(graph):
    unlocked = {u for c in graph.credentials() for u in c.unlocks}
    tasks = []
    for t in graph.targets():
        if t.kind != "mock_host":
            continue
        host = t.props["host"]
        tasks.append(Task(id=f"read:{t.id}:/", capability="mock_read", target=t.id,
                          params={"ref": "/"}, tier="recon", scope_host=host))
        if t.id in unlocked:
            tasks.append(Task(id=f"read:{t.id}:/admin", capability="mock_read", target=t.id,
                              params={"ref": "/admin"}, tier="probe", scope_host=host))
    return tasks


def _shell(tmp_path, *, executors, rule, hosts=("lab",), max_tier="probe", budget=50):
    return ControlShell(
        executors=executors,
        planner=FunctionPlanner(rule),
        scope=Scope(hosts=hosts, max_tier=max_tier),
        workspace=Workspace(tmp_path / "run"),
        budget=Budget(budget),
    )


def test_control_grows_surface_and_loots(tmp_path):
    graph = SituationGraph()
    graph.add_target(Target(id="lab", kind="mock_host", props={"host": "lab"}))
    shell = _shell(tmp_path, executors={"mock_read": MockExecutor()}, rule=_mock_rule)
    result = shell.run(graph)

    # Reading / leaked a credential that unlocked /admin, which yielded loot.
    assert len(result.graph.credentials()) == 1
    assert len(result.graph.entities("artifact")) == 1
    assert result.stopped_reason == "no ready tasks"


def test_control_runs_independent_tasks_concurrently(tmp_path):
    # A barrier that only releases if N tasks are in flight at once proves the
    # shell runs independent ready tasks in parallel, not one at a time.
    n = 3
    barrier = threading.Barrier(n, timeout=3)

    class BarrierExecutor(Executor):
        capability = "barrier"

        def run(self, task, graph):
            barrier.wait()  # raises if the others are not running concurrently
            return Observation(entrypoint_id=task.id, action="barrier", raw={})

        def perceive(self, obs):
            return [Fact(kind="ran", about=obs.entrypoint_id)]

    def rule(graph):
        return [
            Task(id=f"b:{t.id}", capability="barrier", target=t.id, scope_host=t.props["host"])
            for t in graph.targets()
        ]

    graph = SituationGraph()
    for i in range(n):
        graph.add_target(Target(id=f"h{i}", kind="mock_host", props={"host": f"h{i}"}))
    shell = _shell(
        tmp_path, executors={"barrier": BarrierExecutor()}, rule=rule,
        hosts=tuple(f"h{i}" for i in range(n)),
    )
    result = shell.run(graph)

    ran = [f for f in result.graph.facts() if f.kind == "ran"]
    assert len(ran) == n  # all cleared the barrier, so they ran together


def test_control_denies_out_of_scope_tasks(tmp_path):
    graph = SituationGraph()
    graph.add_target(Target(id="evil", kind="mock_host", props={"host": "evil.com"}))
    shell = _shell(tmp_path, executors={"mock_read": MockExecutor()}, rule=_mock_rule, hosts=("lab",))
    result = shell.run(graph)

    assert len(result.graph.credentials()) == 0  # the read was never authorized
    assert any(e["kind"] == "scope_denied" for e in shell.ledger.entries())


def test_control_budget_caps_runaway(tmp_path):
    graph = SituationGraph()
    graph.add_target(Target(id="lab", kind="mock_host", props={"host": "lab"}))
    shell = _shell(tmp_path, executors={"mock_read": MockExecutor()}, rule=_mock_rule, budget=1)
    result = shell.run(graph)

    assert result.stopped_reason == "budget exhausted"
    assert result.steps <= 1

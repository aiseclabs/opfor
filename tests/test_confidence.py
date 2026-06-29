from opfor.agent.confidence import band
from opfor.engine.budget import Budget
from opfor.engine.control import ControlShell
from opfor.engine.graph import SituationGraph
from opfor.engine.scope import Scope
from opfor.engine.state import Workspace
from opfor.engine.tasks import Task
from opfor.model import Fact, Observation
from opfor.plugins.base import Executor
from opfor.scenarios.apiscan.endpoint_vuln import EndpointVulnPlanner


def test_band_thresholds():
    assert band(0.1) == "drop"
    assert band(0.2) == "explore"
    assert band(0.5) == "explore"
    assert band(0.6) == "refine"
    assert band(0.79) == "refine"
    assert band(0.8) == "verify"
    assert band(1.0) == "verify"


class _Counter(Executor):
    capability = "noop"

    def __init__(self):
        self.ran = []

    def run(self, task, graph):
        self.ran.append(task.id)
        return Observation(entrypoint_id=task.id, action="noop", raw={})

    def perceive(self, observation):
        return [Fact(kind="done", about=observation.entrypoint_id)]


class _OnePlanner:
    def __init__(self, tasks):
        self._tasks = tasks

    def expand(self, graph):
        return list(self._tasks)


def test_control_shell_drops_below_confidence_floor(tmp_path):
    ex = _Counter()
    tasks = [
        Task(id="hi", capability="noop", target="h", tier="recon", scope_host="h", confidence=0.7),
        Task(id="lo", capability="noop", target="h", tier="recon", scope_host="h", confidence=0.3),
    ]
    shell = ControlShell(
        executors={"noop": ex}, planner=_OnePlanner(tasks),
        scope=Scope(hosts=("h",), max_tier="recon"),
        workspace=Workspace(tmp_path), budget=Budget(50), confidence_floor=0.5,
    )
    shell.run(SituationGraph())
    assert ex.ran == ["hi"]  # the 0.3 task was pruned below the 0.5 floor


def test_default_floor_runs_everything(tmp_path):
    ex = _Counter()
    tasks = [Task(id="lo", capability="noop", target="h", tier="recon", scope_host="h", confidence=0.1)]
    shell = ControlShell(
        executors={"noop": ex}, planner=_OnePlanner(tasks),
        scope=Scope(hosts=("h",), max_tier="recon"),
        workspace=Workspace(tmp_path), budget=Budget(50),  # default floor 0.0
    )
    shell.run(SituationGraph())
    assert ex.ran == ["lo"]


def test_fuzz_confidence_is_evidence_driven():
    from opfor.model import Endpoint

    graph = SituationGraph()
    # `file` matches the traversal probe affinity (evidence); `xyz` matches nothing.
    graph.add_entity(Endpoint(id="GET /dl", props={
        "host": "h", "method": "GET", "path": "/dl", "params": ["file", "xyz"]}))
    tasks = EndpointVulnPlanner().expand(graph)
    trav_confs = {round(t.confidence, 2) for t in tasks if "traversal" in t.id}
    # The traversal probe gets 0.8 on the `file` param (evidence) and 0.35 on `xyz`.
    assert 0.8 in trav_confs and 0.35 in trav_confs

"""Mock and web scenarios on the control shell, plus suspend/resume."""

from pathlib import Path

from opfor.engine.graph import SituationGraph
from opfor.engine.tasks import Task
from opfor.model import Target
from opfor.runner import run_campaign
from opfor.scenarios.web.executors import WebGetExecutor
from opfor.scenarios.web.planner import WebPlanner

CAMPAIGN = Path(__file__).resolve().parents[1] / "campaigns" / "localhost-demo"


# --- mock scenario, surface grows from state -------------------------------


def test_mock_campaign_grows_surface_and_loots(tmp_path):
    result = run_campaign(CAMPAIGN, run_dir=tmp_path / "run", budget=50)
    # The admin page did not exist at the start: it became reachable only after
    # reading the index leaked a credential that unlocked the target.
    assert len(result.graph.entities("artifact")) == 1
    assert len(result.graph.credentials()) == 1
    assert result.done
    assert result.stopped_reason == "no ready tasks"


def test_suspend_on_budget_then_resume_completes(tmp_path):
    run_dir = tmp_path / "run"
    first = run_campaign(CAMPAIGN, run_dir=run_dir, budget=1)
    assert not first.done
    assert first.stopped_reason == "budget exhausted"
    assert len(first.graph.entities("artifact")) == 0  # only got as far as the index

    second = run_campaign(CAMPAIGN, run_dir=run_dir, resume=True, budget=50)
    assert second.done
    assert len(second.graph.entities("artifact")) == 1  # resume read the admin page


def test_resume_of_finished_run_is_idempotent(tmp_path):
    run_dir = tmp_path / "run"
    run_campaign(CAMPAIGN, run_dir=run_dir, budget=50)
    again = run_campaign(CAMPAIGN, run_dir=run_dir, resume=True, budget=50)
    assert again.done
    assert len(again.graph.entities("artifact")) == 1


# --- web scenario, crawl grows from discovered links -----------------------


def test_web_executor_discovers_same_host_links(stub_server):
    host = stub_server.split("//", 1)[1].split(":")[0]
    ex = WebGetExecutor()
    task = Task(id="webget:root", capability="web_get", target=stub_server,
                params={"url": stub_server + "/", "path": "/"}, tier="recon", scope_host=host)
    facts = ex.perceive(ex.run(task, None))
    paths = {e.props["path"] for f in facts for e in f.yields}
    # /admin and /about are same-host links; the offsite example.com link is dropped.
    assert {"/admin", "/about"} <= paths
    assert not any("example.com" in e.props["url"] for f in facts for e in f.yields)


def test_web_planner_emits_get_for_seed_and_crawled_paths():
    from opfor.model import Endpoint

    graph = SituationGraph()
    graph.add_target(Target(id="http://h", kind="web_host", props={"host": "h", "paths": ["/"]}))
    graph.add_entity(Endpoint(id="GET /admin", props={
        "host": "h", "method": "GET", "path": "/admin", "source": "crawl", "target": "http://h"}))
    caps = {(t.capability, t.params["path"]) for t in WebPlanner().expand(graph)}
    assert ("web_get", "/") in caps
    assert ("web_get", "/admin") in caps

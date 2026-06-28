from pathlib import Path

from opfor.agent.brain import MockBrain
from opfor.engine.graph import SituationGraph
from opfor.engine.loop import AttackLoop
from opfor.engine.scope import Scope
from opfor.engine.state import Workspace
from opfor.model import Artifact, Entrypoint, Fact, Observation, Target
from opfor.plugins.base import Hand
from opfor.runner import run_campaign

CAMPAIGN = Path(__file__).resolve().parents[1] / "campaigns" / "localhost-demo"


def test_mock_campaign_grows_surface_and_loots(tmp_path):
    result = run_campaign(CAMPAIGN, run_dir=tmp_path / "run", budget=50)
    refs = {ep.ref for ep in result.graph.entrypoints()}
    # The admin entrypoint did not exist at the start, it appeared only after
    # reading the index leaked a credential.
    assert "/admin" in refs
    assert len(result.graph.entities("artifact")) == 1
    assert result.done
    assert result.stopped_reason.startswith("brain stopped")


def test_suspend_on_budget_then_resume_completes(tmp_path):
    run_dir = tmp_path / "run"
    first = run_campaign(CAMPAIGN, run_dir=run_dir, budget=1)
    assert not first.done
    assert first.stopped_reason == "budget exhausted"
    assert len(first.graph.entities("artifact")) == 0

    second = run_campaign(CAMPAIGN, run_dir=run_dir, resume=True, budget=50)
    assert second.done
    assert len(second.graph.entities("artifact")) == 1


def test_resume_of_finished_run_is_idempotent(tmp_path):
    run_dir = tmp_path / "run"
    run_campaign(CAMPAIGN, run_dir=run_dir, budget=50)
    again = run_campaign(CAMPAIGN, run_dir=run_dir, resume=True, budget=50)
    assert again.done
    assert len(again.graph.entities("artifact")) == 1


# --- async, constraint 3, across separate loop instances ------------------


class _AsyncHand(Hand):
    """One entrypoint whose result arrives later, like a phishing reply."""

    name = "async-test"

    def enumerate(self, target, graph):
        return [
            Entrypoint(
                id=f"{target.id}::send",
                target_id=target.id,
                kind="message",
                ref="send",
                actions=("send",),
                props={"action_tiers": {"send": "recon"}},
            )
        ]

    def act(self, entrypoint, action, params):
        return Observation(
            entrypoint_id=entrypoint.id,
            action=action,
            params=params,
            pending=True,
            handle="reply-1",
        )

    def normalize(self, observation):
        if observation.raw.get("reply"):
            return [
                Fact(
                    kind="reply",
                    about=observation.entrypoint_id,
                    yields=(Artifact(id="loot:reply", kind="reply", props=observation.raw),),
                )
            ]
        return [Fact(kind="sent", about=observation.entrypoint_id)]


def _async_loop(workspace):
    return AttackLoop(
        hand=_AsyncHand(),
        playbook="async test",
        scope=Scope(hosts=("h",), max_tier="recon"),
        brain=MockBrain(),
        workspace=workspace,
        budget=50,
    )


def test_async_result_delivered_then_resumed_in_new_loop(tmp_path):
    workspace = Workspace(tmp_path / "run")
    graph = SituationGraph()
    graph.add_target(Target(id="t", kind="msg_host", props={"host": "h"}))

    first = _async_loop(workspace).run(graph)
    # The act is outstanding, so the run suspended rather than finished.
    assert not first.done
    assert "async" in first.stopped_reason

    # A late result arrives, then a fresh loop instance resumes the run.
    _async_loop(workspace).deliver("reply-1", {"reply": "clicked the link"})
    resumed = _async_loop(workspace).resume()

    assert resumed.done
    assert any(a.id == "loot:reply" for a in resumed.graph.entities("artifact"))

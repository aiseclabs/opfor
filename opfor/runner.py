"""Assemble a campaign, a scenario, and an engine into a run.

This is the seam where the four layers meet: data source, executors/hands,
knowledge, and engine. A ControlScenario runs on the task-graph control shell
(the recon path); a classic Scenario runs on the older entrypoint loop (mock,
web). Both end with the same triage + report step, which is engine-agnostic.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from opfor.agent.brain import Brain, MockBrain
from opfor.agent.triage import triage_findings
from opfor.campaign import Campaign
from opfor.engine.budget import Budget
from opfor.engine.control import ControlShell
from opfor.engine.graph import SituationGraph
from opfor.engine.loop import AttackLoop
from opfor.engine.state import Workspace
from opfor.report import render
from opfor.scenarios.base import ControlScenario
from opfor.scenarios.registry import get_scenario


def run_campaign(
    campaign_dir: str | Path,
    *,
    run_dir: str | Path | None = None,
    resume: bool = False,
    brain: Brain | None = None,
    budget: int = 50,
    triage_complete: Callable[[str], str] | None = None,
):
    campaign = Campaign.load(campaign_dir)
    scenario = get_scenario(campaign.scenario_name)
    workspace = Workspace(run_dir or Path("runs") / campaign.name)

    if isinstance(scenario, ControlScenario):
        result, ledger = _run_control(scenario, campaign, workspace, budget)
    else:
        result, ledger = _run_loop(scenario, campaign, workspace, budget, brain, resume)

    _finalize(result.graph, ledger, result.stopped_reason, workspace, triage_complete)
    return result


def _run_control(scenario, campaign, workspace, budget):
    shell = ControlShell(
        executors=scenario.executors,
        planner=scenario.planner,
        scope=campaign.scope,
        workspace=workspace,
        budget=Budget(budget),
    )
    graph = SituationGraph()
    for target in campaign.targets:
        graph.add_target(target)
    result = shell.run(graph)
    return result, shell.ledger


def _run_loop(scenario, campaign, workspace, budget, brain, resume):
    loop = AttackLoop(
        hand=scenario.hand(),
        playbook=scenario.playbook(),
        scope=campaign.scope,
        brain=brain or MockBrain(),
        workspace=workspace,
        budget=budget,
    )
    if resume:
        result = loop.resume()
    else:
        graph = SituationGraph()
        for target in campaign.targets:
            graph.add_target(target)
        result = loop.run(graph)
    return result, loop.ledger


def _finalize(graph, ledger, stopped_reason, workspace, triage_complete):
    # Verification stage: a model rules each finding real or a false positive.
    verdicts = None
    if triage_complete is not None:
        findings = list(graph.entities("finding"))
        verdicts = triage_findings(findings, triage_complete)
        confirmed = sum(1 for v in verdicts.values() if v["verdict"] == "confirmed")
        false_pos = sum(1 for v in verdicts.values() if v["verdict"] == "false_positive")
        ledger.append("triage", findings=len(findings), confirmed=confirmed, false_positive=false_pos)
    workspace.report_file.write_text(
        render(graph, ledger, stopped_reason=stopped_reason, verdicts=verdicts)
    )

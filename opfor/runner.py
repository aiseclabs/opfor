"""Assemble a campaign, a scenario, and a brain into a run.

This is the seam where the four layers meet, data source, hand, knowledge, and
engine. The engine itself stays unaware of any of them, it only sees a hand, a
playbook, a scope, and a brain.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from opfor.agent.brain import Brain, MockBrain
from opfor.agent.triage import triage_findings
from opfor.campaign import Campaign
from opfor.engine.graph import SituationGraph
from opfor.engine.loop import AttackLoop, RunResult
from opfor.engine.state import Workspace
from opfor.report import render
from opfor.scenarios.registry import get_scenario


def run_campaign(
    campaign_dir: str | Path,
    *,
    run_dir: str | Path | None = None,
    resume: bool = False,
    brain: Brain | None = None,
    budget: int = 50,
    triage_complete: Callable[[str], str] | None = None,
) -> RunResult:
    campaign = Campaign.load(campaign_dir)
    scenario = get_scenario(campaign.scenario_name)
    workspace = Workspace(run_dir or Path("runs") / campaign.name)
    brain = brain or MockBrain()

    loop = AttackLoop(
        hand=scenario.hand(),
        playbook=scenario.playbook(),
        scope=campaign.scope,
        brain=brain,
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

    # Verification stage: a model rules each finding real or a false positive.
    verdicts = None
    if triage_complete is not None:
        findings = list(result.graph.entities("finding"))
        verdicts = triage_findings(findings, triage_complete)
        confirmed = sum(1 for v in verdicts.values() if v["verdict"] == "confirmed")
        false_pos = sum(1 for v in verdicts.values() if v["verdict"] == "false_positive")
        loop.ledger.append(
            "triage", findings=len(findings), confirmed=confirmed, false_positive=false_pos
        )

    workspace.report_file.write_text(
        render(
            result.graph,
            loop.ledger,
            stopped_reason=result.stopped_reason,
            verdicts=verdicts,
        )
    )
    return result

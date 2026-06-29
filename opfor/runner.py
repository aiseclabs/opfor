"""Assemble a campaign, a scenario, and the engine into a run.

This is the seam where the layers meet: data source (campaign), executors and a
planner (scenario), and the control shell (engine). Every scenario runs on the
one engine, the task-graph control shell, and every run ends with the same triage
plus report step, which is engine-agnostic.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from opfor.agent.triage import triage_findings
from opfor.campaign import Campaign
from opfor.engine.budget import Budget
from opfor.engine.control import ControlShell
from opfor.engine.graph import SituationGraph
from opfor.engine.state import Workspace
from opfor.model import Fact
from opfor.report import render
from opfor.scenarios.registry import get_scenario


def run_campaign(
    campaign_dir: str | Path,
    *,
    run_dir: str | Path | None = None,
    resume: bool = False,
    budget: int = 50,
    triage_complete: Callable[[str], str] | None = None,
):
    campaign = Campaign.load(campaign_dir)
    scenario = get_scenario(campaign.scenario_name)
    workspace = Workspace(run_dir or Path("runs") / campaign.name)

    shell = ControlShell(
        executors=scenario.executors,
        planner=scenario.planner,
        scope=campaign.scope,
        workspace=workspace,
        budget=Budget(budget),
    )
    if resume:
        result = shell.resume()
    else:
        graph = SituationGraph()
        for target in campaign.targets:
            graph.add_target(target)
        # Record the vantage on the blackboard so the report can state what the
        # reachability claims are relative to. Survives checkpoint/resume.
        graph.absorb([Fact(kind="vantage", about="campaign", data={"vantage": campaign.vantage})])
        result = shell.run(graph)

    _finalize(result.graph, shell.ledger, result.stopped_reason, workspace, triage_complete)
    return result


def _finalize(graph, ledger, stopped_reason, workspace, triage_complete):
    # Verification-as-currency: the oracle verdicts produced in the run (the
    # verify stage re-proved each finding) are the source of truth, read off the
    # graph. The model only advises on findings that carry no replayable proof.
    findings = list(graph.entities("finding"))
    verdicts: dict[str, dict] = {}
    for f in graph.facts():
        if f.kind == "verdict":
            verdicts[f.data["finding"]] = {"verdict": f.data["verdict"], "reason": f.data["reason"]}
    unverifiable = [fnd for fnd in findings if fnd.id not in verdicts]
    if unverifiable and triage_complete is not None:
        advised = triage_findings(unverifiable, triage_complete)
        for fid, v in advised.items():
            verdicts[fid] = {"verdict": "unverifiable", "reason": f"no PoC oracle; model says {v['verdict']}: {v.get('reason', '')}"}
    else:
        for fnd in unverifiable:
            verdicts[fnd.id] = {"verdict": "unverifiable", "reason": "no PoC oracle available for this finding type"}
    if findings:
        ledger.append(
            "triage",
            findings=len(findings),
            confirmed=sum(1 for v in verdicts.values() if v["verdict"] == "confirmed"),
            false_positive=sum(1 for v in verdicts.values() if v["verdict"] == "false_positive"),
            unverifiable=sum(1 for v in verdicts.values() if v["verdict"] == "unverifiable"),
        )
    workspace.report_file.write_text(
        render(graph, ledger, stopped_reason=stopped_reason, verdicts=verdicts or None)
    )

"""The opfor command line."""

from __future__ import annotations

import argparse
import sys

from opfor.runner import run_campaign
from opfor.scenarios.registry import known_scenarios


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="opfor", description="Universal offensive-security engine")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run a campaign")
    run.add_argument("campaign", help="path to a campaign directory")
    run.add_argument("--run-dir", default=None, help="where to write state, ledger, report")
    run.add_argument("--resume", action="store_true", help="resume from the last checkpoint")
    run.add_argument("--budget", type=int, default=50, help="max steps")
    run.add_argument(
        "--brain",
        choices=("mock", "model", "hybrid"),
        default="mock",
        help="mock is offline scripted, model asks a model every step, "
        "hybrid auto-runs recon and asks a model only for judgment",
    )
    run.add_argument(
        "--model",
        default="claude-sonnet-4-6",
        help="model id when --brain model (needs ANTHROPIC_API_KEY)",
    )
    run.add_argument(
        "--no-triage",
        action="store_true",
        help="skip the model triage of findings (on by default with a model brain)",
    )
    run.add_argument(
        "--triage",
        action="store_true",
        help="force model triage of findings even with the mock brain (needs ANTHROPIC_API_KEY)",
    )

    sub.add_parser("scenarios", help="list registered scenarios")

    args = parser.parse_args(argv)

    if args.command == "scenarios":
        for name in known_scenarios():
            print(name)
        return 0

    if args.command == "run":
        brain = None
        triage_complete = None
        wants_triage = args.triage or (args.brain in ("model", "hybrid") and not args.no_triage)
        if args.brain in ("model", "hybrid") or wants_triage:
            from opfor.agent.providers import anthropic_complete
        if args.brain in ("model", "hybrid"):
            from opfor.agent.brain import HybridBrain, ModelBrain

            model_brain = ModelBrain(anthropic_complete(args.model))
            brain = model_brain if args.brain == "model" else HybridBrain(model_brain)
        if wants_triage:
            triage_complete = anthropic_complete(args.model, max_tokens=4096)
        result = run_campaign(
            args.campaign,
            run_dir=args.run_dir,
            resume=args.resume,
            budget=args.budget,
            brain=brain,
            triage_complete=triage_complete,
        )
        print(f"stopped after {result.steps} steps: {result.stopped_reason}")
        print(f"report: {result.workspace.report_file}")
        print(f"ledger: {result.workspace.ledger_file}")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())

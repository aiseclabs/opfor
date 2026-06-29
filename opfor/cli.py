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
        "--model",
        default="claude-sonnet-4-6",
        help="model id for finding triage (needs ANTHROPIC_API_KEY)",
    )
    run.add_argument(
        "--triage",
        action="store_true",
        help="model triage of findings, rules each one real or a false positive",
    )

    sub.add_parser("scenarios", help="list registered scenarios")

    new = sub.add_parser("new-campaign", help="scaffold a new campaign directory")
    new.add_argument("name", help="campaign / org name (becomes the directory)")
    new.add_argument("--domain", required=True, help="a confirmed root domain in scope")
    new.add_argument("--org", default=None, help="org keyword seed (defaults to name)")
    new.add_argument("--vantage", default="public", help="public / vpn / internal / whitelisted-ip")
    new.add_argument("--dir", default="campaigns", help="base directory to create the campaign under")

    args = parser.parse_args(argv)

    if args.command == "scenarios":
        for name in known_scenarios():
            print(name)
        return 0

    if args.command == "new-campaign":
        from opfor.scaffold import new_campaign

        path = new_campaign(args.name, domain=args.domain, org=args.org, vantage=args.vantage, base_dir=args.dir)
        print(f"created campaign: {path}")
        print(f"  edit {path}/scope.yaml and {path}/inventory.md, then: opfor run {path}")
        return 0

    if args.command == "run":
        triage_complete = None
        if args.triage:
            from opfor.agent.providers import anthropic_complete

            triage_complete = anthropic_complete(args.model, max_tokens=4096)
        result = run_campaign(
            args.campaign,
            run_dir=args.run_dir,
            resume=args.resume,
            budget=args.budget,
            triage_complete=triage_complete,
        )
        print(f"stopped after {result.steps} steps: {result.stopped_reason}")
        print(f"report: {result.workspace.report_file}")
        print(f"ledger: {result.workspace.ledger_file}")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())

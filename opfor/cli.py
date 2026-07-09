"""The command line entry point.

Two commands, `scenarios` lists what is registered, and `run` drives the attacksurface
scenario from an org name to a Markdown report. Keys are read from the environment, so a
caller sources a `.env` first. The run stays within the hosts named on the command line,
scope is deny-by-default, so nothing is probed that was not authorized here.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from opfor.core import Budget, Node, Scope, World, markdown, run
from opfor.scenarios.attacksurface import build, inventory
from opfor.scenarios.attacksurface.types import Org
from opfor.scenarios.registry import known_scenarios


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="opfor", description="Universal offensive-security engine")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("scenarios", help="list the registered scenarios")

    run_cmd = sub.add_parser("run", help="run the attacksurface scenario and write a report")
    run_cmd.add_argument("org", help="the organization to map, such as a company name")
    run_cmd.add_argument("--domain", action="append", default=[], metavar="ROOT",
                         help="a hint root domain and an authorized host, repeatable")
    run_cmd.add_argument("--class", dest="classes", action="append", default=[], metavar="CLASS",
                         help="restrict to an asset class such as domain or github, repeatable")
    run_cmd.add_argument("--budget", type=int, default=20000, help="the step budget cap")
    run_cmd.add_argument("--out", metavar="FILE", help="write the report here rather than stdout")

    args = parser.parse_args(argv)
    if args.command == "scenarios":
        for name in known_scenarios():
            print(name)
        return 0
    return _run(args)


def _run(args) -> int:
    world = World()
    world.add(Node(id=f"org:{args.org}", type="org",
                   payload=Org(name=args.org, domains=tuple(args.domain), classes=tuple(args.classes))))
    report = run(build(), world,
                 scope=Scope(max_tier="recon", hosts=tuple(args.domain)),
                 budget=Budget(args.budget))
    text = markdown(report, title=f"{args.org} attack surface", sections=inventory(world))
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {args.out}, status {report.status}, {len(report.findings)} finding(s)")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

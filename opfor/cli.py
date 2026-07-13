"""The command line entry point.

Two commands, `scenarios` lists what is registered, `run` drives one scenario to closure
or suspension against a seed the operator supplies. A seed is roots, subdomains, or both,
given inline or loaded from a file, and a file path comes from the flag or, when the flag
is absent, from the matching `OPFOR_*` environment variable, so a fixed target lives in
`.env` and a one-off is a flag. The seed is resolved separately from the run, so the
resolution is testable without touching the network or the model.
"""

from __future__ import annotations

import argparse
import sys

from opfor import __version__
from opfor.scenarios.registry import known_scenarios


def _resolve_seed(args) -> tuple[str, tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """Resolve command input into a target name, seed roots, seed hosts, and scope hosts.

    A flag wins over the environment. Roots and hosts fold to registrable roots and
    probeable hosts through the same normalization a seed file uses. The scope hosts are
    the roots plus the registrable root of every host, so a subdomain is authorized by its
    root. Fails loud when no seed is given, an empty run is an operator error not a result.
    """
    from opfor.scenarios.attacksurface import config
    from opfor.scenarios.attacksurface.net import registrable_root
    from opfor.scenarios.attacksurface.classes.domain.sources import (
        hosts_from_file,
        roots_from_file,
    )

    roots = list(args.root or [])
    roots_path = args.roots or config.roots_file()
    if roots_path:
        roots += roots_from_file(roots_path)
    hosts = list(args.host or [])
    hosts_path = args.hosts or config.hosts_file()
    if hosts_path:
        hosts += hosts_from_file(hosts_path)

    roots = tuple(dict.fromkeys(roots))
    hosts = tuple(dict.fromkeys(hosts))
    if not roots and not hosts:
        raise SystemExit(
            "no seed given, pass --root or --roots, or --host or --hosts, "
            "or set OPFOR_ROOTS_FILE or OPFOR_HOSTS_FILE")

    name = args.name or config.target_name() or (roots[0] if roots else registrable_root(hosts[0]))
    scope_hosts = tuple(dict.fromkeys(list(roots) + [registrable_root(h) for h in hosts]))
    return name, roots, hosts, scope_hosts


def _run(args) -> int:
    from opfor.core import Budget, Scope
    from opfor.core.engine import run as engine_run
    from opfor.scenarios.attacksurface import seed as attacksurface_seed
    from opfor.scenarios.registry import get_scenario

    seed_builders = {"attacksurface": attacksurface_seed}
    if args.scenario not in seed_builders:
        raise SystemExit(f"scenario {args.scenario!r} has no run seed builder, "
                         f"runnable: {', '.join(sorted(seed_builders))}")

    name, roots, hosts, scope_hosts = _resolve_seed(args)
    world = seed_builders[args.scenario](name, domains=roots, hosts=hosts)
    scope = Scope(max_tier=args.tier, hosts=scope_hosts, authorized=args.authorize)
    report = engine_run(get_scenario(args.scenario), world,
                        scope=scope, budget=Budget(args.budget))
    _print_report(report)
    return 0 if report.closed else 1


def _print_report(report) -> None:
    print(f"scenario: {report.scenario}")
    print(f"status: {report.status}  reached: {report.reached.name}  "
          f"terminal: {report.terminal.name}")
    for note in report.notes:
        print(f"note: {note}")
    print(f"findings: {len(report.findings)}")
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    for finding in sorted(report.findings, key=lambda f: order.get(f.severity, 9)):
        print(f"  [{finding.severity}] {finding.title} -> {finding.where}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="opfor", description="Universal offensive-security engine")
    parser.add_argument("--version", action="version", version=f"opfor {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("scenarios", help="list the registered scenarios")

    run = sub.add_parser("run", help="run a scenario against a seed")
    run.add_argument("scenario", help="the scenario to run")
    run.add_argument("--name", help="the target name, defaults to OPFOR_TARGET or the first root")
    run.add_argument("--root", action="append", help="a seed root domain, repeatable")
    run.add_argument("--roots", help="a file of seed roots, defaults to OPFOR_ROOTS_FILE")
    run.add_argument("--host", action="append", help="a seed subdomain host, repeatable")
    run.add_argument("--hosts", help="a file of seed hosts, defaults to OPFOR_HOSTS_FILE")
    run.add_argument("--tier", default="recon", help="the scope tier ceiling, default recon")
    run.add_argument("--authorize", action="store_true", help="record the intrusive-tier authorization")
    run.add_argument("--budget", type=int, default=500, help="the task budget, default 500")

    args = parser.parse_args(argv)
    if args.command == "scenarios":
        for name in known_scenarios():
            print(name)
        return 0
    return _run(args)


if __name__ == "__main__":
    sys.exit(main())

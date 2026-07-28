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
from pathlib import Path

from opfor import __version__
from opfor.core import env_float, env_int
from opfor.envfile import load_env_file
from opfor.report import default_output, persist, report_text
from opfor.scenarios.registry import known_scenarios

# Load a working-directory .env before the run reads its OPFOR_* config, so a fixed target and
# the backend settings live in the file without a manual source. A value already exported in the
# shell wins over the file, see load_env_file.
_ENV_LOADED = load_env_file()


def _env_int(name: str, default: int) -> int:
    """The kernel's integer env rail, with a set-but-unparsable value surfaced as a clean CLI
    error rather than a traceback. The parse contract lives in `core.env`, invariant 5."""
    try:
        return env_int(name, default)
    except ValueError as exc:
        raise SystemExit(str(exc))


def _env_float(name: str, default: float) -> float:
    """The kernel's float env rail, surfaced as a clean CLI error on a bad value, invariant 5."""
    try:
        return env_float(name, default)
    except ValueError as exc:
        raise SystemExit(str(exc))


def _run(args) -> int:
    from opfor.core import Budget, Checkpoint, restore, resume_checkpoint
    from opfor.core.engine import run as engine_run
    from opfor.scenarios.registry import run_adapter

    # The scenario owns how a CLI request becomes its seeded world, scope, and built scenario,
    # exposed through the registry, so the CLI holds no scenario specifics. An unknown or
    # fixture-only scenario fails loud here rather than in a scenario-specific branch.
    try:
        adapter = run_adapter(args.scenario)
        name, world, scope, scenario = adapter(
            name=args.name, roots=tuple(args.root or []), roots_file=args.roots or "",
            hosts=tuple(args.host or []), hosts_file=args.hosts or "", tier=args.tier,
            authorized=args.authorize)
    except (KeyError, ValueError) as exc:
        raise SystemExit(str(exc))

    outdir = Path(args.output) if args.output else default_output(name)
    ckpt = outdir / "checkpoint.json"
    # Retry and the per-task wall-clock are engine rails. They have safe defaults, and the
    # environment overrides them for a flaky network or a slow one, an int and a float in seconds.
    retries = _env_int("OPFOR_TASK_RETRIES", 2)
    timeout = _env_float("OPFOR_TASK_TIMEOUT", 600.0)

    if getattr(args, "resume", False) and ckpt.exists():
        # Continue a run a crash or a suspend left a checkpoint for, from where it stopped rather
        # than from SEED. The seed args still name the target, the world comes from the checkpoint.
        state = restore(Checkpoint.from_json(ckpt.read_text(encoding="utf-8")), scenario)
        state.checkpoint_path = ckpt
        state.max_retries = retries
        state.task_timeout = timeout
        # Raise the budget ceiling to the resumed run's, else it resumes with the exhausted budget
        # that stopped it and suspends again at once. Already-spent steps still count against it.
        state.budget.max_steps = args.budget
        world = state.world
        report = resume_checkpoint(state)
    else:
        # The directory must exist before the run so the first checkpoint can be written. A
        # directory it cannot make disables checkpointing rather than failing the run.
        try:
            outdir.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError:
            ckpt = None
        report = engine_run(scenario, world, scope=scope, budget=Budget(args.budget),
                            max_retries=retries, task_timeout=timeout, checkpoint_path=ckpt)
    print(report_text(report))
    written = persist(report, world, name, getattr(args, "output", None))
    if written is not None:
        print(f"written: {written}/findings.json, {written}/report.md")
    return 0 if report.closed else 1


def main(argv: list[str] | None = None) -> int:
    if _ENV_LOADED:
        n = len(_ENV_LOADED)
        plural = "s" if n != 1 else ""
        print(f"loaded {n} setting{plural} from .env: {', '.join(_ENV_LOADED)}", file=sys.stderr)
    parser = argparse.ArgumentParser(prog="opfor", description="Universal offensive-security engine")
    parser.add_argument("--version", action="version", version=f"opfor {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("scenarios", help="list the registered scenarios")

    run = sub.add_parser("run", help="run a scenario against a seed")
    run.add_argument("scenario", help="the scenario to run")
    run.add_argument("--name", help="the target name, defaults to OPFOR_TARGET or the first root")
    # A seed root and a seed host are the generic slots the CLI stays scenario-agnostic over. The
    # scenario reads them in its own terms, attacksurface as a root domain and a subdomain host.
    run.add_argument("--root", dest="root", action="append", metavar="ROOT",
                     help="a seed root, a root domain for attacksurface, repeatable")
    run.add_argument("--roots", help="a file of seed roots, defaults to OPFOR_ROOTS_FILE")
    run.add_argument("--host", dest="host", action="append", metavar="HOST",
                     help="a seed host, a subdomain for attacksurface, repeatable")
    run.add_argument("--hosts", help="a file of seed hosts, defaults to OPFOR_HOSTS_FILE")
    run.add_argument("--tier", default="recon", help="the scope tier ceiling, default recon")
    run.add_argument("--authorize", action="store_true", help="record the intrusive-tier authorization")
    run.add_argument("--resume", action="store_true",
                     help="continue from a checkpoint in the output directory rather than starting fresh")
    run.add_argument("--budget", type=int, default=500, help="the task budget, default 500")
    run.add_argument("--output",
                     help="the run output directory for findings.json and report.md, defaults "
                          "to a user-private location under XDG_STATE_HOME or ~/.local/state")

    args = parser.parse_args(argv)
    if args.command == "scenarios":
        for name in known_scenarios():
            print(name)
        return 0
    return _run(args)


if __name__ == "__main__":
    raise SystemExit(main())
